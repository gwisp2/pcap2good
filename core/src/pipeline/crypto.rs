//! Session key discovery and command decryption.

use std::collections::HashMap;
use std::sync::Arc;

use protobuf::Message;
use rsa::RsaPrivateKey;
use tracing::debug;

use crate::auto_artifactarium::crypto::{bruteforce, decrypt_command, lookup_initial_key};
use crate::auto_artifactarium::r#gen::protos::PacketHead;
use crate::auto_artifactarium::unk_util::matches_get_player_token_rsp;

use super::command::GameCommand;
use super::flow::FlowId;
use super::kcp::KcpMessage;
use super::udp::Direction;
use super::{DiagnosticSink, DropReason, Stage, Timestamp};

/// Decrypted application payload, possibly containing multiple commands.
pub struct GamePacket {
    pub flow: FlowId,
    pub direction: Direction,
    pub timestamp: Timestamp,
    pub payload: Vec<u8>,
}

#[derive(Clone)]
pub enum Key {
    Dispatch(Vec<u8>),
    Session(Vec<u8>),
}

#[derive(Clone, Debug)]
pub enum KeyEvent {
    DispatchKeyFound,
    SessionKeyFound,
    PossibleSeedsUpdated { count: usize },
    SessionKeyLost,
}

pub enum DecryptOutput {
    Packet(GamePacket),
    Key(KeyEvent),
}

pub struct CommandDecryptor {
    pub flow: FlowId,
    pub key: Option<Key>,
    pub client_seed: Option<u64>,
    pub sent_time: Option<u64>,
    pub possible_seeds: Vec<u64>,
    pub rsa_keys: Arc<Vec<RsaPrivateKey>>,
    pub initial_keys: Arc<HashMap<u16, Vec<u8>>>,
}

impl CommandDecryptor {
    pub fn new(
        flow: FlowId,
        initial_keys: Arc<HashMap<u16, Vec<u8>>>,
        rsa_keys: Arc<Vec<RsaPrivateKey>>,
    ) -> Self {
        Self {
            flow,
            key: None,
            client_seed: None,
            sent_time: None,
            possible_seeds: Vec::new(),
            rsa_keys,
            initial_keys,
        }
    }

    pub fn consume(
        &mut self,
        message: KcpMessage,
        diagnostics: &mut DiagnosticSink,
    ) -> Vec<DecryptOutput> {
        let mut output = Vec::new();
        let timestamp = message.timestamp;

        let Some(key) = self.resolve_key(&message.payload, timestamp, diagnostics, &mut output)
        else {
            return output;
        };

        let mut data = message.payload;
        decrypt_command(&key, &mut data);
        let packet = GamePacket {
            flow: message.flow,
            direction: message.direction,
            timestamp,
            payload: data,
        };

        self.inspect_login_response(&packet, &mut output);

        output.push(DecryptOutput::Packet(packet));
        output
    }

    fn resolve_key(
        &mut self,
        data: &[u8],
        timestamp: Timestamp,
        diagnostics: &mut DiagnosticSink,
        output: &mut Vec<DecryptOutput>,
    ) -> Option<Vec<u8>> {
        match self.key.clone() {
            None => {
                let key = match lookup_initial_key(&self.initial_keys, data) {
                    Some(key) => key,
                    None => {
                        debug!("no initial dispatch key found");
                        diagnostics.report(
                            Stage::Decrypt,
                            Some(self.flow),
                            Some(timestamp),
                            DropReason::UnknownDispatchKey,
                        );
                        return None;
                    }
                };
                debug!("found initial decryption key");
                self.key = Some(Key::Dispatch(key.clone()));
                output.push(DecryptOutput::Key(KeyEvent::DispatchKeyFound));
                Some(key)
            }

            Some(Key::Dispatch(key)) => {
                let mut test = data.to_vec();
                decrypt_command(&key, &mut test);
                if looks_like_command(&test) {
                    return Some(key);
                }

                let seeds = self.possible_seeds.clone();
                for server_seed in seeds {
                    if let Some(client_seed) = self.client_seed
                        && let Some((client_seed, key)) =
                            bruteforce(client_seed, server_seed, data.to_vec())
                    {
                        self.client_seed = Some(client_seed);
                        self.key = Some(Key::Session(key.clone()));
                        debug!("found session key");
                        output.push(DecryptOutput::Key(KeyEvent::SessionKeyFound));
                        return Some(key);
                    }

                    if let Some(sent_time) = self.sent_time
                        && let Some((client_seed, key)) =
                            bruteforce(sent_time, server_seed, data.to_vec())
                    {
                        self.client_seed = Some(client_seed);
                        self.key = Some(Key::Session(key.clone()));
                        debug!("found session key");
                        output.push(DecryptOutput::Key(KeyEvent::SessionKeyFound));
                        return Some(key);
                    }
                }

                debug!("could not derive a session key from the dispatch key");
                diagnostics.report(
                    Stage::Decrypt,
                    Some(self.flow),
                    Some(timestamp),
                    DropReason::UnknownDispatchKey,
                );
                None
            }

            Some(Key::Session(key)) => {
                let mut test = data.to_vec();
                decrypt_command(&key, &mut test);
                if looks_like_command(&test) {
                    return Some(key);
                }

                debug!("invalidated session key");
                self.key = None;
                output.push(DecryptOutput::Key(KeyEvent::SessionKeyLost));
                diagnostics.report(
                    Stage::Decrypt,
                    Some(self.flow),
                    Some(timestamp),
                    DropReason::InvalidSessionKey,
                );
                None
            }
        }
    }

    fn inspect_login_response(&mut self, packet: &GamePacket, output: &mut Vec<DecryptOutput>) {
        if !matches!(self.key, Some(Key::Dispatch(_))) {
            return;
        }

        let Some((command, _)) = GameCommand::parse_one(&packet.payload) else {
            return;
        };
        let Some(possible_seeds) =
            matches_get_player_token_rsp(command.body.clone(), self.rsa_keys.as_ref().clone())
        else {
            return;
        };

        self.possible_seeds = possible_seeds;
        output.push(DecryptOutput::Key(KeyEvent::PossibleSeedsUpdated {
            count: self.possible_seeds.len(),
        }));
        debug!(
            seeds = self.possible_seeds.len(),
            "setting new possible session seeds"
        );

        if let Ok(header) = PacketHead::parse_from_bytes(&command.header) {
            self.sent_time = Some(header.sent_ms);
            debug!(sent_time = header.sent_ms, "setting new send time");
        }
    }
}

fn looks_like_command(data: &[u8]) -> bool {
    data.len() >= 12
        && data[0] == 0x45
        && data[1] == 0x67
        && data[data.len() - 2] == 0x89
        && data[data.len() - 1] == 0xAB
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_command_magic() {
        assert!(looks_like_command(&[
            0x45, 0x67, 0, 0, 0, 0, 0, 0, 0, 0, 0x89, 0xAB
        ]));
        assert!(!looks_like_command(&[0x45, 0x67, 0x89, 0xAB]));
        assert!(!looks_like_command(&[0; 12]));
    }
}
