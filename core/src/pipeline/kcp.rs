//! KCP reassembly, one instance per flow and direction.

use kcp::{KCP_OVERHEAD, Kcp, get_conv};
use tracing::{debug, trace};

use super::flow::FlowId;
use super::udp::Direction;
use super::{DiagnosticSink, DropReason, Stage, Timestamp};

pub struct KcpMessage {
    pub flow: FlowId,
    pub direction: Direction,
    pub timestamp: Timestamp,
    pub payload: Vec<u8>,
}

pub struct KcpReassembler {
    direction: Direction,
    conv_id: Option<u32>,
    kcp: Option<Kcp<Vec<u8>>>,
    time_base: Timestamp,
}

impl KcpReassembler {
    pub fn new(direction: Direction) -> Self {
        Self {
            direction,
            conv_id: None,
            kcp: None,
            time_base: Timestamp::default(),
        }
    }

    pub fn receive(
        &mut self,
        timestamp: Timestamp,
        segments: &[u8],
        diagnostics: &mut DiagnosticSink,
    ) -> Vec<Vec<u8>> {
        let Some(conv_id) = validate_kcp_segment(segments) else {
            diagnostics.report(Stage::Kcp, None, Some(timestamp), DropReason::KcpHeader);
            return Vec::new();
        };

        if self.kcp.is_none() {
            debug!(?self.direction, conv_id, "new KCP conversation");
            self.conv_id = Some(conv_id);
            self.time_base = timestamp;
            self.kcp = Some(new_kcp(conv_id));
        }

        if self.conv_id != Some(conv_id) {
            debug!(
                expected = ?self.conv_id,
                received = conv_id,
                "packet did not belong to the conversation"
            );
            diagnostics.report(
                Stage::Kcp,
                None,
                Some(timestamp),
                DropReason::KcpConversationMismatch,
            );
            return Vec::new();
        }

        trace!("KCP segment data: {}", bytes_as_hex(segments));

        let Some(segments) = reformat_kcp_segments(segments) else {
            diagnostics.report(Stage::Kcp, None, Some(timestamp), DropReason::KcpHeader);
            return Vec::new();
        };

        let Some(kcp) = self.kcp.as_mut() else {
            return Vec::new();
        };

        match kcp.input(&segments) {
            Ok(size) => trace!(size, "KCP input successful"),
            Err(error) => {
                debug!("could not input to KCP: {error}");
                diagnostics.report(Stage::Kcp, None, Some(timestamp), DropReason::KcpHeader);
                return Vec::new();
            }
        }

        let mut received = Vec::new();
        while let Ok(size) = kcp.peeksize() {
            let mut bytes = vec![0; size];
            match kcp.recv(&mut bytes) {
                Ok(_) => received.push(bytes),
                Err(error) => {
                    debug!("could not receive KCP bytes: {error}");
                    break;
                }
            }
        }

        let clock = timestamp.millis_since(self.time_base);
        if let Err(error) = kcp.update(clock) {
            debug!("could not update KCP state: {error}");
        }

        received
    }
}

fn new_kcp(conv_id: u32) -> Kcp<Vec<u8>> {
    let mut kcp = Kcp::new(conv_id, Vec::new());
    kcp.set_wndsize(1024, 1024);
    kcp
}

fn validate_kcp_segment(payload: &[u8]) -> Option<u32> {
    if payload.len() <= KCP_OVERHEAD {
        debug!(len = payload.len(), "KCP header was too short");
        return None;
    }
    Some(get_conv(payload))
}

/// Removes the extra four bytes the game inserts at offset 4 of every KCP
/// segment.
fn reformat_kcp_segments(data: &[u8]) -> Option<Vec<u8>> {
    let mut reformatted = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        // 4 bytes conversation id, 4 game-specific bytes, 20 bytes of the
        // regular KCP header, then the content.
        let header_end = offset.checked_add(28)?;
        if header_end > data.len() {
            return None;
        }

        let content_len =
            u32::from_le_bytes(data[offset + 24..offset + 28].try_into().ok()?) as usize;
        let content_start = header_end.checked_add(4)?;
        let content_end = content_start.checked_add(content_len)?;
        if content_end > data.len() {
            return None;
        }

        reformatted.extend_from_slice(&data[offset..offset + 4]);
        reformatted.extend_from_slice(&data[offset + 8..offset + 28]);
        reformatted.extend_from_slice(&data[content_start..content_end]);

        offset = content_end;
    }

    Some(reformatted)
}

fn bytes_as_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(sequence: u32, content: &[u8]) -> Vec<u8> {
        let mut segment = Vec::new();
        segment.extend_from_slice(&1u32.to_le_bytes());
        segment.extend_from_slice(&[0; 4]);
        segment.push(81);
        segment.push(0);
        segment.extend_from_slice(&1024u16.to_le_bytes());
        segment.extend_from_slice(&0u32.to_le_bytes());
        segment.extend_from_slice(&sequence.to_le_bytes());
        segment.extend_from_slice(&0u32.to_le_bytes());
        segment.extend_from_slice(&(content.len() as u32).to_le_bytes());
        segment.extend_from_slice(&[0; 4]);
        segment.extend_from_slice(content);
        segment
    }

    #[test]
    fn reassembles_one_segment() {
        let mut reassembler = KcpReassembler::new(Direction::ToServer);
        let mut diagnostics = DiagnosticSink::default();
        let messages = reassembler.receive(
            Timestamp::from_parts(1, 0),
            &segment(0, b"hello"),
            &mut diagnostics,
        );

        assert_eq!(messages, vec![b"hello".to_vec()]);
        assert!(diagnostics.entries.is_empty());
    }

    #[test]
    fn rejects_truncated_segments() {
        let mut reassembler = KcpReassembler::new(Direction::ToServer);
        let mut diagnostics = DiagnosticSink::default();
        let mut bytes = segment(0, b"hello");
        bytes.truncate(31);

        let messages = reassembler.receive(Timestamp::default(), &bytes, &mut diagnostics);

        assert!(messages.is_empty());
        assert_eq!(diagnostics.entries.len(), 1);
    }
}
