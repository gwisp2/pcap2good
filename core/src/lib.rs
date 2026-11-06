//! GOOD exporter for Genshin Impact packet captures.
//!
//! The library exposes [`decode_capture_file`] and [`decode_capture_bytes`],
//! which return the GOOD document together with capture statistics and
//! warnings. The CLI, browser wrapper and desktop app use this crate.
//!
//! For live capture, feed packets to [`decode::Decoder`] as they arrive and
//! call [`decode::Decoder::snapshot`] (or [`snapshot_outcome`]) to publish
//! statistics and decoded data without ending the session.

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
pub use api::{DecodeOutcome, decode_capture_bytes, decode_capture_file, snapshot_outcome};
pub use pipeline::{DecodeSnapshot, Warning, WarningCode};
pub use player_data::ExportSettings;

#[cfg(target_arch = "wasm32")]
mod wasm;
