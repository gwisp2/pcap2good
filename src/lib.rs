//! Offline GOOD exporter for Genshin Impact packet captures.
//!
//! The library exposes [`decode_capture_file`] and [`decode_capture_bytes`],
//! which return the GOOD document together with capture statistics and
//! warnings. The CLI and the wasm build are thin wrappers around them.

pub mod achievements;
pub mod api;
pub mod auto_artifactarium;
pub mod capture;
pub mod decode;
pub mod gamedata;
pub mod good;
pub mod pipeline;
pub mod player_data;
pub mod proto_json;

pub use achievements::{
    Achievement, AchievementExport, AchievementStore, matches_achievement_packet,
};
pub use api::{DecodeOutcome, decode_capture_bytes, decode_capture_file};
pub use pipeline::{Warning, WarningCode};
pub use player_data::ExportSettings;

#[cfg(target_arch = "wasm32")]
mod wasm;
