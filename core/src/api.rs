//! High-level capture decoding shared by the CLI and the web wrapper.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

use crate::achievements::{AchievementExport, AchievementStore};
use crate::capture::{self, CaptureStats};
use crate::decode::{DecodeResult, DecodeSnapshot, DecodeStats, Decoder};
use crate::good::Good;
use crate::pipeline::flow::{FlowId, FlowOutcome, FlowStats};
use crate::pipeline::{Warning, WarningCode};

/// The decoded GOOD document plus statistics and warnings.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodeOutcome {
    pub good: Good,
    pub capture: CaptureStats,
    pub decode: DecodeStats,
    pub achievements: AchievementExport,
    pub warnings: Vec<Warning>,
    /// The flow whose data is exposed through `good`.
    pub selected_flow: Option<FlowId>,
    /// Every flow found in the capture, in first-seen order. The CLI and web
    /// page use the first one, but the full list is kept for multi-flow users
    /// and tests.
    pub flows: Vec<FlowOutcome>,
}

/// Decodes a capture file.
pub fn decode_capture_file(path: &Path, dump_dir: Option<PathBuf>) -> Result<DecodeOutcome> {
    let mut decoder = Decoder::with_command_dump(dump_dir)?;
    let capture = capture::read_capture_file(path, |frame| decoder.process_frame(frame))?;

    Ok(finish(decoder.finish(capture)))
}

/// Decodes a capture that is already in memory.
pub fn decode_capture_bytes(bytes: &[u8], dump_dir: Option<PathBuf>) -> Result<DecodeOutcome> {
    let mut decoder = Decoder::with_command_dump(dump_dir)?;
    let capture = capture::read_capture_bytes(bytes, |frame| decoder.process_frame(frame))?;

    Ok(finish(decoder.finish(capture)))
}

fn finish(result: DecodeResult) -> DecodeOutcome {
    let DecodeResult {
        capture,
        decode,
        flows,
        diagnostics: _,
    } = result;

    finish_parts(capture, decode, flows)
}

/// Turns a live pipeline snapshot into an outcome, using the same flow
/// selection and warning rules as a finished capture.
pub fn snapshot_outcome(snapshot: DecodeSnapshot) -> DecodeOutcome {
    let DecodeSnapshot {
        capture,
        decode,
        flows,
    } = snapshot;

    finish_parts(capture, decode, flows)
}

fn finish_parts(
    capture: CaptureStats,
    decode: DecodeStats,
    mut flows: Vec<FlowOutcome>,
) -> DecodeOutcome {
    for flow in &mut flows {
        flow.warnings = warnings(&flow.stats);
    }

    let selected_index = flows
        .iter()
        .position(has_player_data)
        .or_else(|| flows.iter().position(|flow| flow.stats.commands > 0))
        .or_else(|| (!flows.is_empty()).then_some(0));
    let selected = selected_index.and_then(|index| flows.get(index));
    let good = selected
        .map(|flow| flow.good.clone())
        .unwrap_or_else(Good::empty);
    let selected_stats = selected.map(|flow| flow.stats).unwrap_or_default();
    let selected_flow = selected.map(|flow| flow.id);

    let mut warnings = warnings(&selected_stats);
    let player_data_flows = flows.iter().filter(|flow| has_player_data(flow)).count();
    if player_data_flows > 1 {
        warnings.push(Warning::new(
            WarningCode::MultipleFlows {
                count: player_data_flows,
            },
            format!(
                "the capture contains {player_data_flows} game flows with player data; only the \
                 first one is exported"
            ),
            "run the decoder per connection if you need every flow",
        ));
    }

    let mut achievement_store = AchievementStore::default();
    for flow in &flows {
        achievement_store.merge(&flow.achievements.achievements);
    }
    let achievements = AchievementExport::from_store(&achievement_store);
    if !achievements.gi_achievements.is_empty() {
        // Achievements are player data too; an achievement-only capture is not
        // a failed decode.
        warnings.retain(|warning| !matches!(warning.code, WarningCode::NoPlayerData));
    }

    DecodeOutcome {
        good,
        capture,
        decode,
        achievements,
        warnings,
        selected_flow,
        flows,
    }
}

fn has_player_data(flow: &FlowOutcome) -> bool {
    flow.stats.item_packets > 0
        || flow.stats.avatar_packets > 0
        || flow.stats.player_prop_packets > 0
        || !flow.good.characters.is_empty()
        || !flow.good.artifacts.is_empty()
        || !flow.good.weapons.is_empty()
}

fn warnings(stats: &FlowStats) -> Vec<Warning> {
    if stats.item_packets != 0 || stats.avatar_packets != 0 || stats.achievement_packets != 0 {
        return Vec::new();
    }

    if stats.handshakes == 0 {
        vec![Warning::new(
            WarningCode::NoHandshake,
            "no connection handshake was found in the capture",
            "start capturing before launching the game",
        )]
    } else if stats.compressed_commands > 0 {
        vec![Warning::new(
            WarningCode::CompressedLogin,
            "the game compressed its login response (Oodle Network TCP), which this decoder \
             cannot decompress",
            "the session key could not be derived; re-capture the session (the login response \
             is not always compressed)",
        )]
    } else {
        vec![Warning::new(
            WarningCode::NoPlayerData,
            "the capture contains no character or inventory data",
            "the game may not have sent its inventory during the capture",
        )]
    }
}
