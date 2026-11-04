//! Link-layer normalization.
//!
//! Captures can use Ethernet, raw IP, Linux cooked capture or BSD loopback.
//! Everything is normalized to an Ethernet frame because the UDP dissector
//! uses `etherparse`'s Ethernet entry point.

use tracing::trace;

use super::{CapturedFrame, DiagnosticSink, DropReason, Stage, Timestamp};

const LINKTYPE_NULL: i32 = 0;
const LINKTYPE_ETHERNET: i32 = 1;
const LINKTYPE_RAW: i32 = 101;
const LINKTYPE_LOOP: i32 = 108;
const LINKTYPE_LINUX_SLL: i32 = 113;
const LINKTYPE_IPV4: i32 = 228;
const LINKTYPE_IPV6: i32 = 229;
const LINKTYPE_LINUX_SLL2: i32 = 276;

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

pub struct EthernetFrame {
    pub timestamp: Timestamp,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct LinkNormalizer {
    pub unsupported_packets: u64,
}

impl LinkNormalizer {
    pub fn consume(
        &mut self,
        frame: CapturedFrame,
        diagnostics: &mut DiagnosticSink,
    ) -> Option<EthernetFrame> {
        let Some(data) = to_ethernet(frame.link_type.0, &frame.data) else {
            self.unsupported_packets += 1;
            diagnostics.report(
                Stage::Link,
                None,
                Some(frame.timestamp),
                DropReason::UnsupportedLinkType,
            );
            trace!(
                link_type = frame.link_type.0,
                "Skipping packet with unsupported link type"
            );
            return None;
        };

        Some(EthernetFrame {
            timestamp: frame.timestamp,
            data,
        })
    }
}

/// Converts a captured frame to an Ethernet frame.
///
/// Returns `None` if the link type is not supported or if the frame is too
/// short to contain the link layer header.
pub fn to_ethernet(linktype: i32, data: &[u8]) -> Option<Vec<u8>> {
    match linktype {
        LINKTYPE_ETHERNET => Some(data.to_vec()),

        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => {
            let ethertype = ip_ethertype(data)?;
            Some(with_ethernet_header(ethertype, data))
        }

        LINKTYPE_LINUX_SLL => {
            // 2 bytes packet type, 2 bytes ARPHRD, 2 bytes address length,
            // 8 bytes address, 2 bytes protocol.
            let (protocol, payload) = data.split_at_checked(16)?;
            let protocol = u16::from_be_bytes([protocol[14], protocol[15]]);
            Some(with_ethernet_header(protocol, payload))
        }

        LINKTYPE_LINUX_SLL2 => {
            // 2 bytes protocol, 2 bytes reserved, 4 bytes interface index,
            // 2 bytes ARPHRD, 1 byte packet type, 1 byte address length,
            // 8 bytes address.
            let (header, payload) = data.split_at_checked(20)?;
            let protocol = u16::from_be_bytes([header[0], header[1]]);
            Some(with_ethernet_header(protocol, payload))
        }

        // BSD loopback: the first four bytes are the address family. pcap
        // stores it in the host byte order of the capturing machine, so try
        // both byte orders.
        LINKTYPE_NULL | LINKTYPE_LOOP => {
            let (header, payload) = data.split_at_checked(4)?;
            let le = u32::from_le_bytes(header.try_into().expect("four bytes"));
            let be = u32::from_be_bytes(header.try_into().expect("four bytes"));
            let family = if is_ip_family(le) { le } else { be };
            let ethertype = match family {
                2 => ETHERTYPE_IPV4,
                24 | 28 | 30 => ETHERTYPE_IPV6,
                _ => return None,
            };
            Some(with_ethernet_header(ethertype, payload))
        }

        _ => None,
    }
}

fn is_ip_family(family: u32) -> bool {
    matches!(family, 2 | 24 | 28 | 30)
}

/// Returns the Ethernet type of a raw IP packet.
fn ip_ethertype(data: &[u8]) -> Option<u16> {
    match data.first().map(|byte| byte >> 4)? {
        4 => Some(ETHERTYPE_IPV4),
        6 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}

fn with_ethernet_header(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETHERNET_HEADER_LEN + payload.len());
    // The sniffer only inspects the EtherType, so dummy MAC addresses are
    // sufficient.
    frame.extend_from_slice(&[0; 12]);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[cfg(test)]
mod tests {
    use super::super::LinkType;
    use super::*;

    fn captured(link_type: i32, data: Vec<u8>) -> CapturedFrame {
        CapturedFrame {
            timestamp: Timestamp::default(),
            link_type: LinkType(link_type),
            data,
        }
    }

    fn ipv4_udp_packet(payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;

        let mut packet = vec![0x45, 0x00];
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[64, 17, 0, 0]);
        packet.extend_from_slice(&[10, 0, 0, 1]);
        packet.extend_from_slice(&[10, 0, 0, 2]);
        packet.extend_from_slice(&22101u16.to_be_bytes());
        packet.extend_from_slice(&40000u16.to_be_bytes());
        packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn normalizes_raw_ip_link_type() {
        let packet = ipv4_udp_packet(b"hello");
        let mut normalizer = LinkNormalizer::default();
        let mut diagnostics = DiagnosticSink::default();
        let frame = normalizer
            .consume(captured(LINKTYPE_RAW, packet.clone()), &mut diagnostics)
            .unwrap();

        assert_eq!(frame.data, with_ethernet_header(ETHERTYPE_IPV4, &packet));
        assert_eq!(normalizer.unsupported_packets, 0);
    }

    #[test]
    fn normalizes_linux_cooked_link_type() {
        let packet = ipv4_udp_packet(b"hello");
        let mut cooked = vec![0, 0, 0, 1, 0, 6];
        cooked.extend_from_slice(&[1, 2, 3, 4, 5, 6, 0, 0]);
        cooked.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        cooked.extend_from_slice(&packet);

        let mut normalizer = LinkNormalizer::default();
        let mut diagnostics = DiagnosticSink::default();
        let frame = normalizer
            .consume(captured(LINKTYPE_LINUX_SLL, cooked), &mut diagnostics)
            .unwrap();

        assert_eq!(frame.data, with_ethernet_header(ETHERTYPE_IPV4, &packet));
    }

    #[test]
    fn normalizes_linux_cooked_v2_link_type() {
        let packet = ipv4_udp_packet(b"hello");
        let mut cooked = Vec::new();
        cooked.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        cooked.extend_from_slice(&[0, 0]);
        cooked.extend_from_slice(&1u32.to_be_bytes());
        cooked.extend_from_slice(&1u16.to_be_bytes());
        cooked.push(0);
        cooked.push(6);
        cooked.extend_from_slice(&[1, 2, 3, 4, 5, 6, 0, 0]);
        cooked.extend_from_slice(&packet);

        let mut normalizer = LinkNormalizer::default();
        let mut diagnostics = DiagnosticSink::default();
        let frame = normalizer
            .consume(captured(LINKTYPE_LINUX_SLL2, cooked), &mut diagnostics)
            .unwrap();

        assert_eq!(frame.data, with_ethernet_header(ETHERTYPE_IPV4, &packet));
    }

    #[test]
    fn unsupported_link_type_is_reported() {
        let mut normalizer = LinkNormalizer::default();
        let mut diagnostics = DiagnosticSink::default();
        let frame = normalizer.consume(captured(999, vec![1, 2, 3]), &mut diagnostics);

        assert!(frame.is_none());
        assert_eq!(normalizer.unsupported_packets, 1);
        assert_eq!(diagnostics.entries.len(), 1);
    }
}
