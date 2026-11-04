//! Per-flow state and the registry that demultiplexes captured packets.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Serialize;

use crate::good::Good;

use super::command::{CommandFramer, DirectedCommand, is_compressed};
use super::crypto::{CommandDecryptor, DecryptOutput};
use super::kcp::{KcpMessage, KcpReassembler};
use super::sink::{CommandRouter, FlowSinkFactory, FlowSinks, ImageStore};
use super::udp::{ClassifiedDatagram, ConnectionEvent, DatagramKind, Direction, FlowKey};
use super::{DiagnosticSink, SharedContext, Timestamp, Warning};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct FlowId(pub u32);

#[derive(Clone, Debug)]
pub struct FlowControl {
    pub flow: FlowId,
    pub direction: Direction,
    pub timestamp: Timestamp,
    pub event: ConnectionEvent,
}

#[derive(Clone, Debug)]
pub struct KcpSegment {
    pub flow: FlowId,
    pub direction: Direction,
    pub timestamp: Timestamp,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum FlowInput {
    Control(FlowControl),
    Segment(KcpSegment),
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowStats {
    pub game_datagrams: u64,
    pub kcp_messages: u64,
    pub commands: u64,
    pub item_packets: u64,
    pub avatar_packets: u64,
    pub player_prop_packets: u64,
    pub handshakes: u64,
    pub compressed_commands: u64,
    pub decryption_failures: u64,
    pub malformed_commands: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowOutcome {
    pub id: FlowId,
    pub key: FlowKey,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub good: Good,
    pub stats: FlowStats,
    pub images: ImageStore,
    pub warnings: Vec<Warning>,
}

pub struct FlowPipeline {
    pub id: FlowId,
    pub key: FlowKey,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,

    pub to_server: KcpReassembler,
    pub to_client: KcpReassembler,
    pub decryptor: CommandDecryptor,
    pub framer: CommandFramer,
    pub router: CommandRouter,

    shared: Arc<SharedContext>,
    stats: FlowStats,
}

pub trait FlowHandler {
    fn consume(&mut self, input: FlowInput, diagnostics: &mut DiagnosticSink);
    fn finish(self) -> FlowOutcome;
}

impl FlowHandler for FlowPipeline {
    fn consume(&mut self, input: FlowInput, diagnostics: &mut DiagnosticSink) {
        let timestamp = match &input {
            FlowInput::Control(control) => control.timestamp,
            FlowInput::Segment(segment) => segment.timestamp,
        };
        self.last_seen = self.last_seen.max(timestamp);
        self.stats.game_datagrams += 1;

        match input {
            FlowInput::Control(control) => {
                if control.event == ConnectionEvent::HandshakeRequested {
                    self.stats.handshakes += 1;
                }
                self.router.on_control(&control, &mut self.stats);
            }
            FlowInput::Segment(segment) => {
                let reassembler = match segment.direction {
                    Direction::ToServer => &mut self.to_server,
                    Direction::ToClient => &mut self.to_client,
                };
                let messages =
                    reassembler.receive(segment.timestamp, &segment.payload, diagnostics);

                for payload in messages {
                    self.stats.kcp_messages += 1;
                    let message = KcpMessage {
                        flow: self.id,
                        direction: segment.direction,
                        timestamp: segment.timestamp,
                        payload,
                    };

                    let outputs = self.decryptor.consume(message, diagnostics);
                    let mut packet_received = false;
                    for output in outputs {
                        match output {
                            DecryptOutput::Key(_) => {}
                            DecryptOutput::Packet(packet) => {
                                packet_received = true;
                                let timestamp = packet.timestamp;
                                let commands = self.framer.consume(packet, diagnostics);
                                for command in commands {
                                    self.stats.commands += 1;
                                    if is_compressed(&command) {
                                        self.stats.compressed_commands += 1;
                                    }
                                    let directed = DirectedCommand {
                                        flow: self.id,
                                        direction: segment.direction,
                                        timestamp,
                                        command,
                                    };
                                    self.router.on_command(&directed, &mut self.stats);
                                }
                            }
                        }
                    }

                    if !packet_received {
                        self.stats.decryption_failures += 1;
                    }
                }
            }
        }
    }

    fn finish(mut self) -> FlowOutcome {
        self.router.finish();
        self.stats.malformed_commands = self.framer.malformed_commands;

        let good = self
            .router
            .sinks
            .player
            .data
            .export_genshin_optimizer(&self.shared.export_settings);
        let images = self.router.sinks.images.store;

        FlowOutcome {
            id: self.id,
            key: self.key,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            good,
            stats: self.stats,
            images,
            warnings: Vec::new(),
        }
    }
}

pub struct FlowPipelineFactory {
    pub shared: Arc<SharedContext>,
    pub sink_factory: Arc<dyn FlowSinkFactory>,
}

impl FlowPipelineFactory {
    pub fn create(&self, id: FlowId, key: FlowKey, first_seen: Timestamp) -> FlowPipeline {
        let sinks: FlowSinks = self.sink_factory.create(id, &key, self.shared.as_ref());

        FlowPipeline {
            id,
            key,
            first_seen,
            last_seen: first_seen,
            to_server: KcpReassembler::new(Direction::ToServer),
            to_client: KcpReassembler::new(Direction::ToClient),
            decryptor: CommandDecryptor::new(
                id,
                self.shared.initial_keys.clone(),
                self.shared.rsa_keys.clone(),
            ),
            framer: CommandFramer::new(id),
            router: CommandRouter::new(sinks),
            shared: self.shared.clone(),
            stats: FlowStats::default(),
        }
    }
}

pub struct FlowRegistry {
    pub factory: FlowPipelineFactory,
    pub current: HashMap<FlowKey, FlowId>,
    pub active: HashMap<FlowId, FlowPipeline>,
    pub finished: Vec<FlowOutcome>,
    pub next_id: u32,
}

impl FlowRegistry {
    pub fn new(shared: Arc<SharedContext>, sink_factory: Arc<dyn FlowSinkFactory>) -> Self {
        Self {
            factory: FlowPipelineFactory {
                shared,
                sink_factory,
            },
            current: HashMap::new(),
            active: HashMap::new(),
            finished: Vec::new(),
            next_id: 1,
        }
    }

    pub fn consume(&mut self, datagram: ClassifiedDatagram, diagnostics: &mut DiagnosticSink) {
        let ClassifiedDatagram {
            flow,
            direction,
            timestamp,
            payload,
            kind,
        } = datagram;

        if matches!(
            kind,
            DatagramKind::Control(ConnectionEvent::HandshakeRequested)
        ) {
            self.close_flow(flow);
        }

        if !self.current.contains_key(&flow) {
            let id = FlowId(self.next_id);
            self.next_id += 1;
            let pipeline = self.factory.create(id, flow, timestamp);
            self.active.insert(id, pipeline);
            self.current.insert(flow, id);
        }

        let id = self.current[&flow];
        let input = match kind {
            DatagramKind::Control(event) => FlowInput::Control(FlowControl {
                flow: id,
                direction,
                timestamp,
                event,
            }),
            DatagramKind::KcpSegment => FlowInput::Segment(KcpSegment {
                flow: id,
                direction,
                timestamp,
                payload,
            }),
        };

        if let Some(pipeline) = self.active.get_mut(&id) {
            pipeline.consume(input, diagnostics);
        }
    }

    fn close_flow(&mut self, key: FlowKey) {
        let Some(id) = self.current.remove(&key) else {
            return;
        };
        if let Some(pipeline) = self.active.remove(&id) {
            self.finished.push(pipeline.finish());
        }
    }

    pub fn finish(mut self) -> Vec<FlowOutcome> {
        let active = std::mem::take(&mut self.active);
        for (_, pipeline) in active {
            self.finished.push(pipeline.finish());
        }

        let mut flows = self.finished;
        flows.sort_by_key(|flow| (flow.first_seen, flow.id));
        flows
    }
}
