//! Command framing and protobuf access.

use protobuf::Message;

use super::crypto::GamePacket;
use super::flow::FlowId;
use super::udp::Direction;
use super::{DiagnosticSink, DropReason, Stage, Timestamp};

#[derive(Clone)]
pub struct GameCommand {
    pub command_id: u16,
    pub header_len: u16,
    pub data_len: u32,
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}

impl GameCommand {
    const HEADER_LEN: usize = 10;
    const TAIL_LEN: usize = 2;

    /// Parses one command from the start of `bytes` and returns it together
    /// with the number of bytes it occupied.
    pub fn parse_one(bytes: &[u8]) -> Option<(Self, usize)> {
        if bytes.len() < Self::HEADER_LEN + Self::TAIL_LEN {
            return None;
        }
        if bytes[0] != 0x45 || bytes[1] != 0x67 {
            return None;
        }

        let command_id = u16::from_be_bytes(bytes[2..4].try_into().ok()?);
        let header_len = u16::from_be_bytes(bytes[4..6].try_into().ok()?);
        let data_len = u32::from_be_bytes(bytes[6..10].try_into().ok()?);

        let total_len = Self::HEADER_LEN
            .checked_add(usize::from(header_len))?
            .checked_add(usize::try_from(data_len).ok()?)?
            .checked_add(Self::TAIL_LEN)?;
        if total_len > bytes.len() {
            return None;
        }
        if bytes[total_len - 2] != 0x89 || bytes[total_len - 1] != 0xAB {
            return None;
        }

        let body_start = Self::HEADER_LEN + usize::from(header_len);
        let body_end = total_len - Self::TAIL_LEN;

        Some((
            Self {
                command_id,
                header_len,
                data_len,
                header: bytes[Self::HEADER_LEN..body_start].to_vec(),
                body: bytes[body_start..body_end].to_vec(),
            },
            total_len,
        ))
    }

    pub fn try_new(bytes: &[u8]) -> Option<Self> {
        let (command, used) = Self::parse_one(bytes)?;
        (used == bytes.len()).then_some(command)
    }

    pub fn parse_proto<T: Message>(&self) -> protobuf::Result<T> {
        T::parse_from_bytes(&self.body)
    }
}

impl std::fmt::Debug for GameCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GameCommand")
            .field("command_id", &self.command_id)
            .field("header_len", &self.header_len)
            .field("data_len", &self.data_len)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct DirectedCommand {
    pub flow: FlowId,
    pub direction: Direction,
    pub timestamp: Timestamp,
    pub command: GameCommand,
}

pub struct CommandFramer {
    pub flow: FlowId,
    pub pending: Vec<u8>,
    pub malformed_commands: u64,
}

impl CommandFramer {
    pub fn new(flow: FlowId) -> Self {
        Self {
            flow,
            pending: Vec::new(),
            malformed_commands: 0,
        }
    }

    pub fn consume(
        &mut self,
        packet: GamePacket,
        diagnostics: &mut DiagnosticSink,
    ) -> Vec<GameCommand> {
        let mut data = std::mem::take(&mut self.pending);
        if data.is_empty() {
            data = packet.payload;
        } else {
            data.extend_from_slice(&packet.payload);
        }

        let mut commands = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            match GameCommand::parse_one(&data[offset..]) {
                Some((command, used)) if used > 0 => {
                    offset += used;
                    commands.push(command);
                }
                _ => {
                    let reason = if data.len() - offset >= 2
                        && data[offset] == 0x45
                        && data[offset + 1] == 0x67
                    {
                        DropReason::CommandLength
                    } else {
                        DropReason::CommandMagic
                    };
                    diagnostics.report(
                        Stage::Frame,
                        Some(self.flow),
                        Some(packet.timestamp),
                        reason,
                    );
                    self.malformed_commands += 1;
                    break;
                }
            }
        }

        commands
    }
}

/// Detects commands whose body was compressed by the game before it was sent.
///
/// The protocol header carries the decompressed size in field 8, which lets us
/// spot compressed bodies even though we cannot decode them.
pub fn is_compressed(command: &GameCommand) -> bool {
    let Some(decompressed_len) = packet_head_field(&command.header, 8) else {
        return false;
    };
    decompressed_len > command.body.len() as u64
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

#[cfg(test)]
mod tests {
    use super::*;

    fn command(command_id: u16, header: &[u8], body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x45, 0x67]);
        bytes.extend_from_slice(&command_id.to_be_bytes());
        bytes.extend_from_slice(&(header.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(&[0x89, 0xAB]);
        bytes
    }

    #[test]
    fn parses_header_and_body_separately() {
        let bytes = command(42, &[0x40, 0x07], &[0x08, 0x01]);
        let (parsed, used) = GameCommand::parse_one(&bytes).unwrap();

        assert_eq!(used, bytes.len());
        assert_eq!(parsed.command_id, 42);
        assert_eq!(parsed.header, vec![0x40, 0x07]);
        assert_eq!(parsed.body, vec![0x08, 0x01]);
    }

    #[test]
    fn parses_multiple_concatenated_commands() {
        let mut bytes = command(1, &[], &[0x08, 0x01]);
        bytes.extend_from_slice(&command(2, &[], &[0x08, 0x02]));

        let (first, used) = GameCommand::parse_one(&bytes).unwrap();
        let (second, second_used) = GameCommand::parse_one(&bytes[used..]).unwrap();

        assert_eq!(first.command_id, 1);
        assert_eq!(second.command_id, 2);
        assert_eq!(used + second_used, bytes.len());
    }

    #[test]
    fn rejects_bad_magic_and_lengths() {
        let mut bytes = command(1, &[], &[0x08, 0x01]);
        bytes[0] = 0;
        assert!(GameCommand::parse_one(&bytes).is_none());

        let mut bytes = command(1, &[], &[0x08, 0x01]);
        bytes.truncate(bytes.len() - 1);
        assert!(GameCommand::parse_one(&bytes).is_none());
    }

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
