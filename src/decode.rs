//! Turns captured game packets into player data.

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use auto_artifactarium::{
    ConnectionPacket, GameCommand, GamePacket, GameSniffer, matches_avatar_packet,
    matches_item_packet,
};
use base64::prelude::*;
use flate2::read::GzDecoder;
use serde::Serialize;

use crate::gamedata::GameData;
use crate::good;
use crate::player_data::{ExportSettings, PlayerData};
use crate::proto_json;

static DATABASE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/game_data.gz"));

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodeStats {
    /// Number of decrypted game commands.
    pub commands: u64,
    /// Number of `PlayerStoreNotify` commands (the player's items).
    pub item_packets: u64,
    /// Number of `AvatarDataNotify` commands (the player's characters).
    pub avatar_packets: u64,
    /// Number of connection handshakes seen in the capture.
    pub handshakes: u64,
    /// Number of commands whose body the game compressed before sending.
    pub compressed_commands: u64,
}

pub struct Decoder {
    player_data: PlayerData,
    sniffer: GameSniffer,
    stats: DecodeStats,
    dump_dir: Option<PathBuf>,
    dumped_commands: u64,
}

impl Decoder {
    /// Creates a decoder without writing decoded commands anywhere.
    pub fn new() -> Result<Self> {
        Self::with_command_dump(None)
    }

    /// Creates a decoder. When `dump_dir` is set, the payload of every decoded
    /// command is written there, which helps diagnosing captures.
    pub fn with_command_dump(dump_dir: Option<PathBuf>) -> Result<Self> {
        let game_data = GameData::from_reader(GzDecoder::new(DATABASE))
            .context("Failed to load the embedded game data")?;

        if let Some(dir) = &dump_dir {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("Failed to create {}", dir.display()))?;
        }

        let keys = load_keys()?;
        let sniffer = GameSniffer::new().set_initial_keys(keys);

        Ok(Self {
            player_data: PlayerData::new(game_data),
            sniffer,
            stats: DecodeStats::default(),
            dump_dir,
            dumped_commands: 0,
        })
    }

    /// Feeds one captured Ethernet frame to the game sniffer.
    pub fn process_frame(&mut self, frame: Vec<u8>) {
        match self.sniffer.receive_packet(frame) {
            Some(GamePacket::Commands(commands)) => {
                for command in commands {
                    self.stats.commands += 1;
                    tracing::debug!(command_id = command.command_id, "Decoded game command");
                    self.dump_command(&command);
                    self.track_compression(&command);

                    if let Some(items) = matches_item_packet(&command) {
                        tracing::info!("Found item packet with {} items", items.len());
                        self.player_data.process_items(&items);
                        self.stats.item_packets += 1;
                    } else if let Some(avatars) = matches_avatar_packet(&command) {
                        tracing::info!("Found avatar packet with {} avatars", avatars.len());
                        self.player_data.process_characters(&avatars);
                        self.stats.avatar_packets += 1;
                    }
                }
            }
            Some(GamePacket::Connection(packet)) => match packet {
                ConnectionPacket::HandshakeRequested => {
                    self.stats.handshakes += 1;
                    tracing::info!("Game handshake requested");
                }
                ConnectionPacket::Disconnected => {
                    tracing::info!("Game connection closed");
                }
                ConnectionPacket::HandshakeEstablished => {
                    tracing::debug!("Game handshake established");
                }
                ConnectionPacket::SegmentData(_, _) => {}
            },
            None => {}
        }
    }

    pub fn stats(&self) -> DecodeStats {
        self.stats
    }

    pub fn export(&self, settings: &ExportSettings) -> good::Good {
        self.player_data.export_genshin_optimizer(settings)
    }

    fn dump_command(&mut self, command: &GameCommand) {
        let Some(dir) = &self.dump_dir else {
            return;
        };

        self.dumped_commands += 1;
        let name = format!("{:04}-{}", self.dumped_commands, command.command_id);

        let path = dir.join(format!("{name}.bin"));
        if let Err(e) = std::fs::write(&path, &command.proto_data) {
            tracing::warn!("Failed to write {}: {e}", path.display());
        }

        // The header and the body are separate protobuf messages, so decode
        // them independently instead of treating the payload as one message.
        let (header, body) = command
            .proto_data
            .split_at_checked(command.header_len as usize)
            .unwrap_or((&[], &command.proto_data));
        let decoded = serde_json::json!({
            "header": proto_json::decode_or_base64(header),
            "body": proto_json::decode_or_base64(body),
        });

        let path = dir.join(format!("{name}.json"));
        match serde_json::to_string_pretty(&decoded) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::warn!("Failed to write {}: {e}", path.display());
                }
            }
            Err(e) => tracing::warn!("Failed to encode {}: {e}", path.display()),
        }
    }

    /// Detects commands whose body was compressed by the game before it was
    /// sent (Genshin 7.1 does this to the login response on some sessions).
    ///
    /// The protocol header carries the decompressed size in field 8, which
    /// lets us spot the compressed bodies even though we cannot decode them.
    fn track_compression(&mut self, command: &GameCommand) {
        let header_len = command.header_len as usize;
        let Some((header, body)) = command.proto_data.split_at_checked(header_len) else {
            return;
        };
        let Some(decompressed_len) = packet_head_field(header, 8) else {
            return;
        };

        if decompressed_len > body.len() as u64 {
            self.stats.compressed_commands += 1;
            tracing::debug!(
                command_id = command.command_id,
                body_len = body.len(),
                decompressed_len,
                "Command body is compressed"
            );
        }
    }
}

/// Reads an unsigned varint from the start of `bytes`.
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;

    for (index, byte) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
    }

    None
}

/// Returns the value of `field` in a serialized protobuf message.
fn packet_head_field(bytes: &[u8], field: u64) -> Option<u64> {
    let mut rest = bytes;

    loop {
        let (key, used) = read_varint(rest)?;
        rest = rest.get(used..)?;
        let number = key >> 3;
        let wire_type = key & 7;

        match wire_type {
            // Varint.
            0 => {
                let (value, used) = read_varint(rest)?;
                rest = rest.get(used..)?;
                if number == field {
                    return Some(value);
                }
            }
            // Fixed 64 bit.
            1 => rest = rest.get(8..)?,
            // Length delimited.
            2 => {
                let (len, used) = read_varint(rest)?;
                rest = rest.get(used..)?;
                rest = rest.get(usize::try_from(len).ok()?..)?;
            }
            // Fixed 32 bit.
            5 => rest = rest.get(4..)?,
            _ => return None,
        }

        if rest.is_empty() {
            return None;
        }
    }
}

fn load_keys() -> Result<HashMap<u16, Vec<u8>>> {
    let keys: HashMap<u16, String> = serde_json::from_slice(include_bytes!("../keys/gi.json"))
        .context("Failed to parse keys")?;

    keys.iter()
        .map(|(key, value)| -> Result<_, _> { Ok((*key, BASE64_STANDARD.decode(value)?)) })
        .collect::<Result<HashMap<_, _>>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_head_field_finds_decompressed_size() {
        // field 3 = 1, field 6 = 42, field 8 = 25576
        let header = [0x18, 0x01, 0x30, 0x2a, 0x40, 0xe8, 0xc7, 0x01];
        assert_eq!(packet_head_field(&header, 8), Some(25576));
        assert_eq!(packet_head_field(&header, 6), Some(42));
        assert_eq!(packet_head_field(&header, 3), Some(1));
        assert_eq!(packet_head_field(&header, 9), None);
    }

    #[test]
    fn packet_head_field_skips_length_delimited_values() {
        // field 1 = "abc", field 8 = 7
        let header = [0x0a, 0x03, b'a', b'b', b'c', 0x40, 0x07];
        assert_eq!(packet_head_field(&header, 8), Some(7));
    }

    #[test]
    fn packet_head_field_rejects_garbage() {
        assert_eq!(packet_head_field(&[0x0f], 8), None);
        assert_eq!(packet_head_field(&[0x40], 8), None);
    }
}
