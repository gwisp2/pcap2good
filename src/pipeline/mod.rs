//! Packet parsing pipeline.
//!
//! The capture is decoded in layers:
//!
//! ```text
//! CapturedFrame -> EthernetFrame -> UdpPacket -> GameDatagram
//!     -> ClassifiedDatagram -> FlowRegistry -> FlowPipeline -> GameCommand
//! ```
//!
//! `FlowRegistry` keeps one [`flow::FlowPipeline`] per connection, so packets
//! from several clients or reconnects can be interleaved in one capture
//! without sharing KCP or key state.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::capture::CaptureStats;
use crate::gamedata::GameData;
use crate::player_data::ExportSettings;
use rsa::RsaPrivateKey;

pub mod command;
pub mod crypto;
pub mod flow;
pub mod kcp;
pub mod link;
pub mod sink;
pub mod udp;

use self::flow::{FlowRegistry, FlowStats};
use self::link::LinkNormalizer;
use self::sink::FlowSinkFactory;
use self::udp::{GameTrafficFilter, PacketClassifier, UdpDissector};

/// Timestamp of a captured packet.
///
/// pcap timestamps are absolute; internally everything is stored in
/// microseconds so KCP can use a per-flow time base without floating point
/// arithmetic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Timestamp {
    pub micros: u64,
}

impl Timestamp {
    pub fn from_parts(seconds: u64, micros: u32) -> Self {
        Self {
            micros: seconds
                .saturating_mul(1_000_000)
                .saturating_add(u64::from(micros)),
        }
    }

    pub fn from_resolution(seconds: u64, fraction: u64, resolution: u64) -> Self {
        let micros = fraction
            .saturating_mul(1_000_000)
            .checked_div(resolution)
            .unwrap_or(0);
        Self::from_parts(seconds, u32::try_from(micros).unwrap_or(u32::MAX))
    }

    /// Milliseconds elapsed since `earlier`, saturating at `u32::MAX`.
    pub fn millis_since(self, earlier: Timestamp) -> u32 {
        let micros = self.micros.saturating_sub(earlier.micros);
        u32::try_from(micros / 1_000).unwrap_or(u32::MAX)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct LinkType(pub i32);

pub struct CapturedFrame {
    pub timestamp: Timestamp,
    pub link_type: LinkType,
    pub data: Vec<u8>,
}

pub struct SharedContext {
    pub game_data: Arc<GameData>,
    pub initial_keys: Arc<HashMap<u16, Vec<u8>>>,
    pub rsa_keys: Arc<Vec<RsaPrivateKey>>,
    pub export_settings: ExportSettings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Stage {
    Capture,
    Link,
    Udp,
    GameFilter,
    Classify,
    Kcp,
    Decrypt,
    Frame,
    Route,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DropReason {
    UnsupportedLinkType,
    NotIp,
    NotUdp,
    NotGamePort,
    PayloadTooShort,
    KcpHeader,
    KcpConversationMismatch,
    UnknownDispatchKey,
    InvalidSessionKey,
    CommandMagic,
    CommandLength,
    TrailingBytes,
}

#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub stage: Stage,
    pub flow: Option<flow::FlowId>,
    pub timestamp: Option<Timestamp>,
    pub reason: DropReason,
}

#[derive(Default)]
pub struct DiagnosticSink {
    pub entries: Vec<Diagnostic>,
    pub drop_counts: HashMap<Stage, u64>,
}

impl DiagnosticSink {
    pub fn report(
        &mut self,
        stage: Stage,
        flow: Option<flow::FlowId>,
        timestamp: Option<Timestamp>,
        reason: DropReason,
    ) {
        *self.drop_counts.entry(stage).or_default() += 1;
        self.entries.push(Diagnostic {
            stage,
            flow,
            timestamp,
            reason,
        });
    }
}

pub struct StepContext<'a, Output> {
    pub emit: &'a mut dyn FnMut(Output),
    pub diagnostics: &'a mut DiagnosticSink,
}

pub trait Step<Input, Output> {
    fn consume(&mut self, input: Input, ctx: &mut StepContext<'_, Output>);
    fn reset(&mut self);
    fn finish(&mut self, ctx: &mut StepContext<'_, Output>);
}

#[derive(Clone, Debug, Serialize)]
pub struct Warning {
    pub code: WarningCode,
    pub message: String,
    pub hint: Option<String>,
}

impl Warning {
    pub fn new(code: WarningCode, message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: Some(hint.into()),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WarningCode {
    MultipleFlows { count: usize },
    NoHandshake,
    CompressedLogin,
    SessionKeyNotEstablished,
    NoPlayerData,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodeStats {
    pub flows: u64,
    pub commands: u64,
    pub item_packets: u64,
    pub avatar_packets: u64,
    pub handshakes: u64,
    pub compressed_commands: u64,
    pub udp_packets: u64,
    pub game_datagrams: u64,
    pub kcp_messages: u64,
    pub decryption_failures: u64,
    pub malformed_commands: u64,
}

pub struct DecodeResult {
    pub capture: CaptureStats,
    pub decode: DecodeStats,
    pub flows: Vec<flow::FlowOutcome>,
    pub diagnostics: Vec<Diagnostic>,
}

pub struct Pipeline {
    link: LinkNormalizer,
    udp: UdpDissector,
    filter: GameTrafficFilter,
    classifier: PacketClassifier,
    registry: FlowRegistry,
    diagnostics: DiagnosticSink,
    udp_packets: u64,
    game_datagrams: u64,
}

impl Pipeline {
    pub fn new(shared: Arc<SharedContext>, sink_factory: Arc<dyn FlowSinkFactory>) -> Self {
        let registry = FlowRegistry::new(shared, sink_factory);
        Self {
            link: LinkNormalizer::default(),
            udp: UdpDissector,
            filter: GameTrafficFilter::default(),
            classifier: PacketClassifier,
            registry,
            diagnostics: DiagnosticSink::default(),
            udp_packets: 0,
            game_datagrams: 0,
        }
    }

    pub fn process_frame(&mut self, frame: CapturedFrame) {
        let Some(frame) = self.link.consume(frame, &mut self.diagnostics) else {
            return;
        };
        let Some(udp) = self.udp.consume(frame, &mut self.diagnostics) else {
            return;
        };
        self.udp_packets += 1;

        let Some(game) = self.filter.consume(udp, &mut self.diagnostics) else {
            return;
        };
        self.game_datagrams += 1;

        let Some(class) = self.classifier.consume(game, &mut self.diagnostics) else {
            return;
        };
        self.registry.consume(class, &mut self.diagnostics);
    }

    pub fn finish(self, mut capture: CaptureStats) -> DecodeResult {
        let flows = self.registry.finish();
        let mut decode = DecodeStats {
            flows: flows.len() as u64,
            udp_packets: self.udp_packets,
            game_datagrams: self.game_datagrams,
            ..DecodeStats::default()
        };
        for flow in &flows {
            add_stats(&mut decode, &flow.stats);
        }

        capture.unsupported_packets = self.link.unsupported_packets;
        capture.game_packets = self.game_datagrams;

        DecodeResult {
            capture,
            decode,
            flows,
            diagnostics: self.diagnostics.entries,
        }
    }
}

fn add_stats(total: &mut DecodeStats, flow: &FlowStats) {
    total.commands += flow.commands;
    total.item_packets += flow.item_packets;
    total.avatar_packets += flow.avatar_packets;
    total.handshakes += flow.handshakes;
    total.compressed_commands += flow.compressed_commands;
    total.kcp_messages += flow.kcp_messages;
    total.decryption_failures += flow.decryption_failures;
    total.malformed_commands += flow.malformed_commands;
}
