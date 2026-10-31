//! Reads packet captures from disk and feeds the game packets to the decoder.
//!
//! Both the legacy pcap format and pcapng are supported. Captures can use any
//! of the link types that are commonly produced by tcpdump, Wireshark and
//! Npcap; frames are normalized to Ethernet before being handed to
//! [`auto_artifactarium`], which expects an Ethernet header.

use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};
use etherparse::{SlicedPacket, TransportSlice};
use pcap_parser::pcapng::Block;
use pcap_parser::traits::PcapNGPacketBlock;
use pcap_parser::{PcapBlockOwned, PcapError, create_reader};
use serde::Serialize;

/// The game uses these ports for its KCP connection.
pub const PORT_RANGE: (u16, u16) = (22101, 22102);

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

const INPUT_BUFFER_SIZE: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStats {
    /// Number of packet records in the capture.
    pub packets: u64,
    /// Number of packets sent to the decoder (UDP on the game's ports).
    pub game_packets: u64,
    /// Number of packets skipped because their link type is not supported.
    pub unsupported_packets: u64,
    /// Set when the file ended in the middle of a packet or block.
    pub truncated: bool,
}

/// Reads a capture file and calls `on_frame` with an Ethernet frame for each
/// game packet.
pub fn read_capture_file<F>(path: &Path, on_frame: F) -> Result<CaptureStats>
where
    F: FnMut(Vec<u8>),
{
    let file = File::open(path)
        .with_context(|| format!("Failed to open capture file {}", path.display()))?;
    let file_len = file.metadata().map(|m| m.len()).unwrap_or_default();
    if file_len == 0 {
        bail!("Capture file {} is empty", path.display());
    }

    read_capture(file, on_frame)
        .with_context(|| format!("Failed to read capture file {}", path.display()))
}

/// Reads a capture from memory and calls `on_frame` with an Ethernet frame for
/// each game packet.
pub fn read_capture_bytes<F>(bytes: &[u8], on_frame: F) -> Result<CaptureStats>
where
    F: FnMut(Vec<u8>),
{
    if bytes.is_empty() {
        bail!("The capture is empty");
    }

    read_capture(Cursor::new(bytes), on_frame).context("Failed to read the capture")
}

/// Reads every game packet from `reader` and calls `on_frame` with an Ethernet
/// frame for each one.
fn read_capture<R, F>(reader: R, mut on_frame: F) -> Result<CaptureStats>
where
    R: Read + Send,
    F: FnMut(Vec<u8>),
{
    let mut reader = create_reader(INPUT_BUFFER_SIZE, reader)
        .context("Failed to initialise the capture reader")?;

    let mut stats = CaptureStats::default();
    // Link type of each interface in the current section, indexed by
    // interface id. Legacy pcap files only ever have interface 0.
    let mut interfaces: Vec<i32> = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                handle_block(&block, &mut interfaces, &mut stats, &mut on_frame);
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            // The file ends in the middle of a record.
            Err(PcapError::UnexpectedEof) => {
                stats.truncated = true;
                break;
            }
            Err(PcapError::Incomplete(_)) => match reader.refill() {
                Ok(()) => {}
                Err(PcapError::Eof | PcapError::UnexpectedEof) => {
                    stats.truncated = true;
                    break;
                }
                Err(e) => bail!("Failed to read the capture: {e}"),
            },
            Err(PcapError::BufferTooSmall) => {
                let new_size = reader.data().len().saturating_mul(2).max(INPUT_BUFFER_SIZE);
                if !reader.grow(new_size) {
                    bail!("A packet in the capture is too large to be read");
                }
            }
            Err(e) => bail!("Failed to read the capture: {e}"),
        }
    }

    if stats.truncated {
        tracing::warn!("The capture ends in the middle of a packet; the last packet was skipped");
    }

    Ok(stats)
}

fn handle_block<F>(
    block: &PcapBlockOwned<'_>,
    interfaces: &mut Vec<i32>,
    stats: &mut CaptureStats,
    on_frame: &mut F,
) where
    F: FnMut(Vec<u8>),
{
    match block {
        PcapBlockOwned::LegacyHeader(header) => {
            interfaces.clear();
            interfaces.push(header.network.0);
        }
        PcapBlockOwned::Legacy(block) => {
            let linktype = interfaces.first().copied().unwrap_or(LINKTYPE_ETHERNET);
            handle_packet(linktype, block.data, stats, on_frame);
        }
        PcapBlockOwned::NG(Block::SectionHeader(_)) => interfaces.clear(),
        PcapBlockOwned::NG(Block::InterfaceDescription(interface)) => {
            interfaces.push(interface.linktype.0)
        }
        PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
            let linktype = interfaces
                .get(packet.if_id as usize)
                .copied()
                .unwrap_or(LINKTYPE_ETHERNET);
            handle_packet(linktype, packet.packet_data(), stats, on_frame);
        }
        PcapBlockOwned::NG(Block::SimplePacket(packet)) => {
            let linktype = interfaces.first().copied().unwrap_or(LINKTYPE_ETHERNET);
            handle_packet(linktype, packet.packet_data(), stats, on_frame);
        }
        PcapBlockOwned::NG(_) => {}
    }
}

fn handle_packet<F>(linktype: i32, data: &[u8], stats: &mut CaptureStats, on_frame: &mut F)
where
    F: FnMut(Vec<u8>),
{
    stats.packets += 1;

    let Some(frame) = to_ethernet(linktype, data) else {
        stats.unsupported_packets += 1;
        tracing::trace!("Skipping packet with unsupported link type {linktype}");
        return;
    };

    if !is_game_packet(&frame) {
        return;
    }

    stats.game_packets += 1;
    on_frame(frame);
}

/// Returns true if the frame carries UDP traffic on the game's port range.
///
/// Packets with a very short payload are rejected as well: the game sniffer
/// assumes at least one byte is present in the payload.
fn is_game_packet(frame: &[u8]) -> bool {
    let Ok(sliced) = SlicedPacket::from_ethernet(frame) else {
        return false;
    };
    let Some(TransportSlice::Udp(udp)) = sliced.transport else {
        return false;
    };

    let (low, high) = PORT_RANGE;
    let on_game_port =
        (low..=high).contains(&udp.source_port()) || (low..=high).contains(&udp.destination_port());

    on_game_port && udp.payload().len() >= 4
}

/// Converts a captured frame to an Ethernet frame.
///
/// Returns `None` if the link type is not supported or if the frame is too
/// short to contain the link layer header.
fn to_ethernet(linktype: i32, data: &[u8]) -> Option<Vec<u8>> {
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
    // The game sniffer only inspects the EtherType, so dummy MAC addresses are
    // sufficient.
    frame.extend_from_slice(&[0; 12]);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

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

    fn ethernet_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        with_ethernet_header(ethertype, payload)
    }

    fn legacy_pcap(linktype: i32, packets: &[Vec<u8>]) -> Vec<u8> {
        let mut file = Vec::new();
        file.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        file.extend_from_slice(&2u16.to_le_bytes());
        file.extend_from_slice(&4u16.to_le_bytes());
        file.extend_from_slice(&0i32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&65535u32.to_le_bytes());
        file.extend_from_slice(&linktype.to_le_bytes());
        for packet in packets {
            file.extend_from_slice(&0u32.to_le_bytes());
            file.extend_from_slice(&0u32.to_le_bytes());
            file.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            file.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            file.extend_from_slice(packet);
        }
        file
    }

    fn pcapng(linktype: i32, packets: &[Vec<u8>]) -> Vec<u8> {
        fn block(block_type: u32, body: &[u8]) -> Vec<u8> {
            let padded = (body.len() + 3) & !3;
            let total = padded + 12;
            let mut out = Vec::new();
            out.extend_from_slice(&block_type.to_le_bytes());
            out.extend_from_slice(&(total as u32).to_le_bytes());
            out.extend_from_slice(body);
            out.resize(out.len() + (padded - body.len()), 0);
            out.extend_from_slice(&(total as u32).to_le_bytes());
            out
        }

        let mut file = Vec::new();

        // Section header: byte order magic, major, minor, section length.
        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        file.extend_from_slice(&block(0x0a0d_0d0a, &shb));

        // Interface description: link type, reserved, snap length.
        let mut idb = Vec::new();
        idb.extend_from_slice(&(linktype as u16).to_le_bytes());
        idb.extend_from_slice(&0u16.to_le_bytes());
        idb.extend_from_slice(&65535u32.to_le_bytes());
        file.extend_from_slice(&block(0x0000_0001, &idb));

        for packet in packets {
            // Enhanced packet: interface id, timestamp, captured/original length.
            let mut epb = Vec::new();
            epb.extend_from_slice(&0u32.to_le_bytes());
            epb.extend_from_slice(&0u32.to_le_bytes());
            epb.extend_from_slice(&0u32.to_le_bytes());
            epb.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            epb.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            epb.extend_from_slice(packet);
            file.extend_from_slice(&block(0x0000_0006, &epb));
        }

        file
    }

    fn temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("post-irminsul-{}-{name}", std::process::id()));
        fs::write(&path, contents).unwrap();
        path
    }

    fn collect(path: &Path) -> (CaptureStats, Vec<Vec<u8>>) {
        let mut frames = Vec::new();
        let stats = read_capture_file(path, |frame| frames.push(frame)).unwrap();
        (stats, frames)
    }

    fn collect_bytes(contents: &[u8]) -> (CaptureStats, Vec<Vec<u8>>) {
        let mut frames = Vec::new();
        let stats = read_capture_bytes(contents, |frame| frames.push(frame)).unwrap();
        (stats, frames)
    }

    #[test]
    fn reads_a_capture_from_memory() {
        let packet = ethernet_frame(ETHERTYPE_IPV4, &ipv4_udp_packet(b"hello"));
        let contents = legacy_pcap(LINKTYPE_ETHERNET, std::slice::from_ref(&packet));

        let (stats, frames) = collect_bytes(&contents);

        assert_eq!(stats.packets, 1);
        assert_eq!(stats.game_packets, 1);
        assert_eq!(frames, vec![packet]);
    }

    #[test]
    fn empty_memory_capture_is_an_error() {
        assert!(read_capture_bytes(&[], |_| {}).is_err());
    }

    #[test]
    fn reads_legacy_pcap_with_ethernet_link_type() {
        let packet = ethernet_frame(ETHERTYPE_IPV4, &ipv4_udp_packet(b"hello"));
        let path = temp_file(
            "legacy.pcap",
            &legacy_pcap(LINKTYPE_ETHERNET, std::slice::from_ref(&packet)),
        );

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(stats.game_packets, 1);
        assert_eq!(frames, vec![packet]);
    }

    #[test]
    fn reads_pcapng_with_ethernet_link_type() {
        let packet = ethernet_frame(ETHERTYPE_IPV4, &ipv4_udp_packet(b"hello"));
        let path = temp_file(
            "legacy.pcapng",
            &pcapng(LINKTYPE_ETHERNET, std::slice::from_ref(&packet)),
        );

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(stats.game_packets, 1);
        assert_eq!(frames, vec![packet]);
    }

    #[test]
    fn ignores_traffic_on_other_ports() {
        let mut packet = ipv4_udp_packet(b"hello");
        packet[20..22].copy_from_slice(&443u16.to_be_bytes());
        let frame = ethernet_frame(ETHERTYPE_IPV4, &packet);
        let path = temp_file("other-port.pcap", &legacy_pcap(LINKTYPE_ETHERNET, &[frame]));

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(stats.game_packets, 0);
        assert!(frames.is_empty());
    }

    #[test]
    fn normalizes_raw_ip_link_type() {
        let packet = ipv4_udp_packet(b"hello");
        let path = temp_file(
            "raw.pcap",
            &legacy_pcap(LINKTYPE_RAW, std::slice::from_ref(&packet)),
        );

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.game_packets, 1);
        assert_eq!(frames, vec![ethernet_frame(ETHERTYPE_IPV4, &packet)]);
    }

    #[test]
    fn normalizes_linux_cooked_link_type() {
        let packet = ipv4_udp_packet(b"hello");
        let mut cooked = vec![0, 0, 0, 1, 0, 6];
        cooked.extend_from_slice(&[1, 2, 3, 4, 5, 6, 0, 0]);
        cooked.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        cooked.extend_from_slice(&packet);

        let path = temp_file("sll.pcap", &legacy_pcap(LINKTYPE_LINUX_SLL, &[cooked]));

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.game_packets, 1);
        assert_eq!(frames, vec![ethernet_frame(ETHERTYPE_IPV4, &packet)]);
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

        let path = temp_file("sll2.pcap", &legacy_pcap(LINKTYPE_LINUX_SLL2, &[cooked]));

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.game_packets, 1);
        assert_eq!(frames, vec![ethernet_frame(ETHERTYPE_IPV4, &packet)]);
    }

    #[test]
    fn short_udp_payloads_are_ignored() {
        let frame = ethernet_frame(ETHERTYPE_IPV4, &ipv4_udp_packet(b"a"));
        let path = temp_file("short.pcap", &legacy_pcap(LINKTYPE_ETHERNET, &[frame]));

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(stats.game_packets, 0);
        assert!(frames.is_empty());
    }

    #[test]
    fn truncated_udp_payload_is_ignored() {
        let mut frame = ethernet_frame(ETHERTYPE_IPV4, &ipv4_udp_packet(b"hello"));
        frame.truncate(ETHERNET_HEADER_LEN + 20 + 8 + 2);
        let path = temp_file("truncated.pcap", &legacy_pcap(LINKTYPE_ETHERNET, &[frame]));

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(stats.game_packets, 0);
        assert!(frames.is_empty());
    }

    #[test]
    fn truncated_file_is_reported() {
        let packet = ethernet_frame(ETHERTYPE_IPV4, &ipv4_udp_packet(b"hello"));
        let mut contents = legacy_pcap(LINKTYPE_ETHERNET, std::slice::from_ref(&packet));
        contents.extend_from_slice(&[1, 2, 3, 4]);
        let path = temp_file("truncated-file.pcap", &contents);

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert!(stats.truncated);
        assert_eq!(frames, vec![packet]);
    }

    #[test]
    fn unsupported_link_type_is_skipped() {
        let packet = ipv4_udp_packet(b"hello");
        let path = temp_file("unsupported.pcap", &legacy_pcap(999, &[packet]));

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(stats.unsupported_packets, 1);
        assert!(frames.is_empty());
    }
}
