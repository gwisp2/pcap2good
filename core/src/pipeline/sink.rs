//! Final consumers of decoded commands.
//!
//! Sinks are created per flow by a [`FlowSinkFactory`]. The player-data sink
//! owns the matching logic, so the parser no longer needs to know which
//! protobuf messages the exporter cares about.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing::warn;

use crate::achievements::{AchievementStore, matches_achievement_packet};
use crate::auto_artifactarium::r#gen::protos::{AvatarInfo, Item};
use crate::auto_artifactarium::unk_util::{
    matches_avatars_all_data_notify, matches_items_all_data_notify, matches_player_prop_map,
};
use crate::gamedata::GameData;
use crate::player_data::PlayerData;
use crate::proto_json;

use super::SharedContext;
use super::command::DirectedCommand;
use super::flow::{FlowControl, FlowId, FlowStats};
use super::udp::FlowKey;

pub trait CommandSink {
    fn on_command(&mut self, command: &DirectedCommand, stats: &mut FlowStats);
    fn on_control(&mut self, control: &FlowControl, stats: &mut FlowStats);
    fn finish(&mut self);
}

pub struct PlayerDataSink {
    pub data: PlayerData,
}

impl PlayerDataSink {
    pub fn new(game_data: Arc<GameData>) -> Self {
        Self {
            data: PlayerData::new(game_data),
        }
    }
}

impl CommandSink for PlayerDataSink {
    fn on_command(&mut self, command: &DirectedCommand, stats: &mut FlowStats) {
        if let Some(items) = matches_item_packet(command, self.data.game_data()) {
            self.data.process_items(&items);
            stats.item_packets += 1;
        } else if let Some(avatars) = matches_avatar_packet(command) {
            self.data.process_characters(&avatars);
            stats.avatar_packets += 1;
        } else if let Some(props) = matches_player_data_packet(command) {
            self.data.process_player_props(props);
            stats.player_prop_packets += 1;
        }
    }

    fn on_control(&mut self, _control: &FlowControl, _stats: &mut FlowStats) {}

    fn finish(&mut self) {}
}

fn matches_item_packet(command: &DirectedCommand, game_data: &GameData) -> Option<Vec<Item>> {
    matches_items_all_data_notify(&command.command.body, game_data)
}

fn matches_avatar_packet(command: &DirectedCommand) -> Option<Vec<AvatarInfo>> {
    matches_avatars_all_data_notify(&command.command.body)
}

fn matches_player_data_packet(
    command: &DirectedCommand,
) -> Option<std::collections::HashMap<u32, i64>> {
    matches_player_prop_map(&command.command.body)
}

pub struct AchievementSink {
    game_data: Arc<GameData>,
    pub store: AchievementStore,
}

impl AchievementSink {
    pub fn new(game_data: Arc<GameData>) -> Self {
        Self {
            game_data,
            store: AchievementStore::default(),
        }
    }
}

impl CommandSink for AchievementSink {
    fn on_command(&mut self, command: &DirectedCommand, stats: &mut FlowStats) {
        if let Some(achievements) =
            matches_achievement_packet(&command.command.body, &self.game_data)
        {
            // The stardb import format only accepts achievements it knows.
            let achievements: Vec<_> = achievements
                .into_iter()
                .filter(|achievement| self.game_data.is_known_achievement_id(achievement.id))
                .collect();
            self.store.merge(&achievements);
            stats.achievement_packets += 1;
        }
    }

    fn on_control(&mut self, _control: &FlowControl, _stats: &mut FlowStats) {}

    fn finish(&mut self) {}
}

pub struct DumpState {
    pub dir: PathBuf,
    pub counter: u64,
}

#[derive(Clone)]
pub struct CommandDumpSink {
    state: Arc<Mutex<DumpState>>,
}

impl CommandDumpSink {
    pub fn new(state: Arc<Mutex<DumpState>>) -> Self {
        Self { state }
    }
}

impl CommandSink for CommandDumpSink {
    fn on_command(&mut self, command: &DirectedCommand, _stats: &mut FlowStats) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.counter += 1;
        let name = format!("{:04}-{}", state.counter, command.command.command_id);

        let mut payload =
            Vec::with_capacity(command.command.header.len() + command.command.body.len());
        payload.extend_from_slice(&command.command.header);
        payload.extend_from_slice(&command.command.body);

        let path = state.dir.join(format!("{name}.bin"));
        if let Err(error) = fs::write(&path, payload) {
            warn!("Failed to write {}: {error}", path.display());
        }

        let decoded = serde_json::json!({
            "header": proto_json::decode_or_base64(&command.command.header),
            "body": proto_json::decode_or_base64(&command.command.body),
        });
        let path = state.dir.join(format!("{name}.json"));
        match serde_json::to_string_pretty(&decoded) {
            Ok(json) => {
                if let Err(error) = fs::write(&path, json) {
                    warn!("Failed to write {}: {error}", path.display());
                }
            }
            Err(error) => warn!("Failed to encode {}: {error}", path.display()),
        }
    }

    fn on_control(&mut self, _control: &FlowControl, _stats: &mut FlowStats) {}

    fn finish(&mut self) {}
}

pub struct FlowSinks {
    pub player: PlayerDataSink,
    pub achievements: AchievementSink,
    pub dump: Option<CommandDumpSink>,
    pub extra: Vec<Box<dyn CommandSink>>,
}

pub struct CommandRouter {
    pub sinks: FlowSinks,
}

impl CommandRouter {
    pub fn new(sinks: FlowSinks) -> Self {
        Self { sinks }
    }

    pub fn on_command(&mut self, command: &DirectedCommand, stats: &mut FlowStats) {
        self.sinks.player.on_command(command, stats);
        self.sinks.achievements.on_command(command, stats);
        if let Some(dump) = &mut self.sinks.dump {
            dump.on_command(command, stats);
        }
        for sink in &mut self.sinks.extra {
            sink.on_command(command, stats);
        }
    }

    pub fn on_control(&mut self, control: &FlowControl, stats: &mut FlowStats) {
        self.sinks.player.on_control(control, stats);
        if let Some(dump) = &mut self.sinks.dump {
            dump.on_control(control, stats);
        }
        for sink in &mut self.sinks.extra {
            sink.on_control(control, stats);
        }
    }

    pub fn finish(&mut self) {
        self.sinks.player.finish();
        self.sinks.achievements.finish();
        if let Some(dump) = &mut self.sinks.dump {
            dump.finish();
        }
        for sink in &mut self.sinks.extra {
            sink.finish();
        }
    }
}

pub trait FlowSinkFactory: Send + Sync {
    fn create(&self, flow: FlowId, key: &FlowKey, shared: &SharedContext) -> FlowSinks;
}

pub struct DefaultFlowSinkFactory {
    pub dump: Option<Arc<Mutex<DumpState>>>,
}

impl FlowSinkFactory for DefaultFlowSinkFactory {
    fn create(&self, _flow: FlowId, _key: &FlowKey, shared: &SharedContext) -> FlowSinks {
        FlowSinks {
            player: PlayerDataSink::new(shared.game_data.clone()),
            achievements: AchievementSink::new(shared.game_data.clone()),
            dump: self.dump.clone().map(CommandDumpSink::new),
            extra: Vec::new(),
        }
    }
}
