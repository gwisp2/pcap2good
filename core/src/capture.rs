//! Reads packet captures from disk and emits raw link-layer frames.
//!
//! Both the legacy pcap format and pcapng are supported. Link-layer
//! normalization and game-port filtering happen in [`crate::pipeline`].

use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};
use pcap_parser::pcapng::Block;
use pcap_parser::traits::PcapNGPacketBlock;
use pcap_parser::{PcapBlockOwned, PcapError, create_reader};
use serde::Serialize;

use crate::pipeline::{CapturedFrame, LinkType, Timestamp};

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

/// Reads a capture file and calls `on_frame` with each captured frame.
pub fn read_capture_file<F>(path: &Path, on_frame: F) -> Result<CaptureStats>
where
    F: FnMut(CapturedFrame),
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

/// Reads a capture from memory and calls `on_frame` with each captured frame.
pub fn read_capture_bytes<F>(bytes: &[u8], on_frame: F) -> Result<CaptureStats>
where
    F: FnMut(CapturedFrame),
{
    if bytes.is_empty() {
        bail!("The capture is empty");
    }

    read_capture(Cursor::new(bytes), on_frame).context("Failed to read the capture")
}

struct InterfaceInfo {
    link_type: i32,
    ts_resolution: u64,
    ts_offset: i64,
}

impl Default for InterfaceInfo {
    fn default() -> Self {
        Self {
            link_type: 1,
            ts_resolution: 1_000_000,
            ts_offset: 0,
        }
    }
}

/// Reads every packet from `reader` and calls `on_frame` for each one.
fn read_capture<R, F>(reader: R, mut on_frame: F) -> Result<CaptureStats>
where
    R: Read + Send,
    F: FnMut(CapturedFrame),
{
    let mut reader = create_reader(INPUT_BUFFER_SIZE, reader)
        .context("Failed to initialise the capture reader")?;

    let mut stats = CaptureStats::default();
    // Link type and timestamp parameters of each interface in the current
    // section, indexed by interface id. Legacy pcap files only ever have
    // interface 0.
    let mut interfaces: Vec<InterfaceInfo> = Vec::new();
    let mut last_timestamp = Timestamp::default();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                handle_block(
                    &block,
                    &mut interfaces,
                    &mut stats,
                    &mut last_timestamp,
                    &mut on_frame,
                );
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
    interfaces: &mut Vec<InterfaceInfo>,
    stats: &mut CaptureStats,
    last_timestamp: &mut Timestamp,
    on_frame: &mut F,
) where
    F: FnMut(CapturedFrame),
{
    match block {
        PcapBlockOwned::LegacyHeader(header) => {
            interfaces.clear();
            interfaces.push(InterfaceInfo {
                link_type: header.network.0,
                ts_resolution: 1_000_000,
                ts_offset: 0,
            });
        }
        PcapBlockOwned::Legacy(block) => {
            let interface = interfaces.first().copied().unwrap_or_default();
            let timestamp = Timestamp::from_parts(u64::from(block.ts_sec), block.ts_usec);
            handle_packet(
                interface.link_type,
                timestamp,
                block.data,
                stats,
                last_timestamp,
                on_frame,
            );
        }
        PcapBlockOwned::NG(Block::SectionHeader(_)) => interfaces.clear(),
        PcapBlockOwned::NG(Block::InterfaceDescription(interface)) => {
            interfaces.push(InterfaceInfo {
                link_type: interface.linktype.0,
                ts_resolution: interface.ts_resolution().unwrap_or(1_000_000),
                ts_offset: interface.ts_offset(),
            });
        }
        PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
            let interface = interfaces
                .get(packet.if_id as usize)
                .copied()
                .unwrap_or_default();
            let (seconds, fraction) =
                packet.decode_ts(interface.ts_offset.max(0) as u64, interface.ts_resolution);
            let timestamp = Timestamp::from_resolution(
                u64::from(seconds),
                u64::from(fraction),
                interface.ts_resolution,
            );
            handle_packet(
                interface.link_type,
                timestamp,
                packet.packet_data(),
                stats,
                last_timestamp,
                on_frame,
            );
        }
        PcapBlockOwned::NG(Block::SimplePacket(packet)) => {
            let interface = interfaces.first().copied().unwrap_or_default();
            handle_packet(
                interface.link_type,
                *last_timestamp,
                packet.packet_data(),
                stats,
                last_timestamp,
                on_frame,
            );
        }
        PcapBlockOwned::NG(_) => {}
    }
}

fn handle_packet<F>(
    link_type: i32,
    timestamp: Timestamp,
    data: &[u8],
    stats: &mut CaptureStats,
    last_timestamp: &mut Timestamp,
    on_frame: &mut F,
) where
    F: FnMut(CapturedFrame),
{
    stats.packets += 1;
    *last_timestamp = timestamp;
    on_frame(CapturedFrame {
        timestamp,
        link_type: LinkType(link_type),
        data: data.to_vec(),
    });
}

impl Clone for InterfaceInfo {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for InterfaceInfo {}

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
        let mut frame = vec![0; 12];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
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
            std::env::temp_dir().join(format!("pcap2good-{}-{name}", std::process::id()));
        fs::write(&path, contents).unwrap();
        path
    }

    fn collect(path: &Path) -> (CaptureStats, Vec<CapturedFrame>) {
        let mut frames = Vec::new();
        let stats = read_capture_file(path, |frame| frames.push(frame)).unwrap();
        (stats, frames)
    }

    fn collect_bytes(contents: &[u8]) -> (CaptureStats, Vec<CapturedFrame>) {
        let mut frames = Vec::new();
        let stats = read_capture_bytes(contents, |frame| frames.push(frame)).unwrap();
        (stats, frames)
    }

    #[test]
    fn reads_a_capture_from_memory() {
        let packet = ethernet_frame(0x0800, &ipv4_udp_packet(b"hello"));
        let contents = legacy_pcap(1, std::slice::from_ref(&packet));

        let (stats, frames) = collect_bytes(&contents);

        assert_eq!(stats.packets, 1);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, packet);
        assert_eq!(frames[0].link_type, LinkType(1));
    }

    #[test]
    fn empty_memory_capture_is_an_error() {
        assert!(read_capture_bytes(&[], |_| {}).is_err());
    }

    #[test]
    fn reads_legacy_pcap_with_ethernet_link_type() {
        let packet = ethernet_frame(0x0800, &ipv4_udp_packet(b"hello"));
        let path = temp_file(
            "legacy.pcap",
            &legacy_pcap(1, std::slice::from_ref(&packet)),
        );

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(frames[0].data, packet);
    }

    #[test]
    fn reads_pcapng_with_ethernet_link_type() {
        let packet = ethernet_frame(0x0800, &ipv4_udp_packet(b"hello"));
        let path = temp_file("legacy.pcapng", &pcapng(1, std::slice::from_ref(&packet)));

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(frames[0].data, packet);
    }

    #[test]
    fn emits_traffic_on_other_ports() {
        let mut packet = ipv4_udp_packet(b"hello");
        packet[20..22].copy_from_slice(&443u16.to_be_bytes());
        let frame = ethernet_frame(0x0800, &packet);
        let path = temp_file("other-port.pcap", &legacy_pcap(1, &[frame]));

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn truncated_file_is_reported() {
        let packet = ethernet_frame(0x0800, &ipv4_udp_packet(b"hello"));
        let mut contents = legacy_pcap(1, std::slice::from_ref(&packet));
        contents.extend_from_slice(&[1, 2, 3, 4]);
        let path = temp_file("truncated-file.pcap", &contents);

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert!(stats.truncated);
        assert_eq!(frames[0].data, packet);
    }

    #[test]
    fn unsupported_link_type_is_emitted() {
        let packet = ipv4_udp_packet(b"hello");
        let path = temp_file(
            "unsupported.pcap",
            &legacy_pcap(999, std::slice::from_ref(&packet)),
        );

        let (stats, frames) = collect(&path);
        fs::remove_file(path).ok();

        assert_eq!(stats.packets, 1);
        assert_eq!(frames[0].link_type, LinkType(999));
    }

    #[test]
    fn empty_file_is_an_error() {
        let path =
            std::env::temp_dir().join(format!("pcap2good-{}-zero.pcap", std::process::id()));
        fs::write(&path, b"").unwrap();
        assert!(read_capture_file(&path, |_| {}).is_err());
        fs::remove_file(path).ok();
    }
}
