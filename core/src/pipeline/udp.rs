//! UDP parsing, game-port filtering and connection/KCP classification.

use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use serde::Serialize;
use tracing::{debug, trace};

use super::link::EthernetFrame;
use super::{DiagnosticSink, DropReason, Stage, Timestamp};

/// The game uses these ports for its KCP connection.
pub const PORT_RANGE: (u16, u16) = (22101, 22102);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

/// Direction from the game client's perspective.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    ToServer,
    ToClient,
}

impl Direction {
    pub fn opposite(self) -> Self {
        match self {
            Self::ToServer => Self::ToClient,
            Self::ToClient => Self::ToServer,
        }
    }
}

/// Direction-independent flow identity.
///
/// `client` is the ephemeral side, `server` is the game-port side. Both
/// directions of one connection produce the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct FlowKey {
    pub client: Endpoint,
    pub server: Endpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

impl PortRange {
    pub fn contains(self, port: u16) -> bool {
        (self.first..=self.last).contains(&port)
    }
}

impl Default for PortRange {
    fn default() -> Self {
        Self {
            first: PORT_RANGE.0,
            last: PORT_RANGE.1,
        }
    }
}

pub struct UdpPacket {
    pub timestamp: Timestamp,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub payload: Vec<u8>,
}

pub struct GameDatagram {
    pub flow: FlowKey,
    pub direction: Direction,
    pub timestamp: Timestamp,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionEvent {
    HandshakeRequested,
    HandshakeEstablished,
    Disconnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramKind {
    Control(ConnectionEvent),
    KcpSegment,
}

pub struct ClassifiedDatagram {
    pub flow: FlowKey,
    pub direction: Direction,
    pub timestamp: Timestamp,
    pub payload: Vec<u8>,
    pub kind: DatagramKind,
}

#[derive(Default)]
pub struct UdpDissector;

impl UdpDissector {
    pub fn consume(
        &mut self,
        frame: EthernetFrame,
        diagnostics: &mut DiagnosticSink,
    ) -> Option<UdpPacket> {
        let packet = match SlicedPacket::from_ethernet(&frame.data) {
            Ok(packet) => packet,
            Err(error) => {
                debug!("failed to parse Ethernet frame: {error}");
                diagnostics.report(Stage::Udp, None, Some(frame.timestamp), DropReason::NotIp);
                return None;
            }
        };

        let Some(net) = packet.net else {
            diagnostics.report(Stage::Udp, None, Some(frame.timestamp), DropReason::NotIp);
            return None;
        };
        let (source_addr, destination_addr) = match &net {
            NetSlice::Ipv4(ip) => (
                IpAddr::V4(ip.header().source_addr()),
                IpAddr::V4(ip.header().destination_addr()),
            ),
            NetSlice::Ipv6(ip) => (
                IpAddr::V6(ip.header().source_addr()),
                IpAddr::V6(ip.header().destination_addr()),
            ),
        };

        let Some(TransportSlice::Udp(udp)) = packet.transport else {
            diagnostics.report(Stage::Udp, None, Some(frame.timestamp), DropReason::NotUdp);
            return None;
        };

        trace!("parsed UDP packet");
        Some(UdpPacket {
            timestamp: frame.timestamp,
            source: Endpoint {
                addr: source_addr,
                port: udp.source_port(),
            },
            destination: Endpoint {
                addr: destination_addr,
                port: udp.destination_port(),
            },
            payload: udp.payload().to_vec(),
        })
    }
}

#[derive(Default)]
pub struct GameTrafficFilter {
    pub ports: PortRange,
    pub game_datagrams: u64,
}

impl GameTrafficFilter {
    pub fn consume(
        &mut self,
        packet: UdpPacket,
        diagnostics: &mut DiagnosticSink,
    ) -> Option<GameDatagram> {
        let source_is_game = self.ports.contains(packet.source.port);
        let destination_is_game = self.ports.contains(packet.destination.port);

        let (direction, client, server) = match (source_is_game, destination_is_game) {
            (true, true) => {
                // This is unusual (for example a loopback capture). Prefer the
                // destination and keep the packet rather than dropping both
                // directions.
                (Direction::ToServer, packet.source, packet.destination)
            }
            (true, false) => (Direction::ToClient, packet.destination, packet.source),
            (false, true) => (Direction::ToServer, packet.source, packet.destination),
            (false, false) => {
                diagnostics.report(
                    Stage::GameFilter,
                    None,
                    Some(packet.timestamp),
                    DropReason::NotGamePort,
                );
                return None;
            }
        };

        if packet.payload.len() < 4 {
            diagnostics.report(
                Stage::GameFilter,
                None,
                Some(packet.timestamp),
                DropReason::PayloadTooShort,
            );
            return None;
        }

        self.game_datagrams += 1;
        Some(GameDatagram {
            flow: FlowKey { client, server },
            direction,
            timestamp: packet.timestamp,
            payload: packet.payload,
        })
    }
}

#[derive(Default)]
pub struct PacketClassifier;

impl PacketClassifier {
    pub fn consume(
        &mut self,
        datagram: GameDatagram,
        _diagnostics: &mut DiagnosticSink,
    ) -> Option<ClassifiedDatagram> {
        let kind = if datagram.payload.len() <= 20 {
            let code = u32::from_be_bytes(
                datagram.payload[..4]
                    .try_into()
                    .expect("payload has at least four bytes"),
            );
            match code {
                0xFF => DatagramKind::Control(ConnectionEvent::HandshakeRequested),
                404 => DatagramKind::Control(ConnectionEvent::Disconnected),
                _ => DatagramKind::Control(ConnectionEvent::HandshakeEstablished),
            }
        } else {
            DatagramKind::KcpSegment
        };

        trace!(?kind, "classified game datagram");

        Some(ClassifiedDatagram {
            flow: datagram.flow,
            direction: datagram.direction,
            timestamp: datagram.timestamp,
            payload: datagram.payload,
            kind,
        })
    }
}
