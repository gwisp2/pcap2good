//! High-level capture decoding shared by the CLI and the web wrapper.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

use crate::capture::{self, CaptureStats};
use crate::decode::{DecodeStats, Decoder};
use crate::good::Good;
use crate::player_data::ExportSettings;

/// An explanation of why the capture could not be fully decoded.
#[derive(Clone, Debug, Serialize)]
pub struct Warning {
    pub message: String,
    pub hint: Option<String>,
}

impl Warning {
    fn new(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            hint: Some(hint.into()),
        }
    }
}

/// The decoded GOOD document plus statistics and warnings.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodeOutcome {
    pub good: Good,
    pub capture: CaptureStats,
    pub decode: DecodeStats,
    pub warnings: Vec<Warning>,
}

/// Decodes a capture file.
pub fn decode_capture_file(
    path: &Path,
    settings: &ExportSettings,
    dump_dir: Option<PathBuf>,
) -> Result<DecodeOutcome> {
    let mut decoder = Decoder::with_command_dump(dump_dir)?;
    let capture = capture::read_capture_file(path, |frame| decoder.process_frame(frame))?;

    Ok(finish(&decoder, capture, settings))
}

/// Decodes a capture that is already in memory.
pub fn decode_capture_bytes(
    bytes: &[u8],
    settings: &ExportSettings,
    dump_dir: Option<PathBuf>,
) -> Result<DecodeOutcome> {
    let mut decoder = Decoder::with_command_dump(dump_dir)?;
    let capture = capture::read_capture_bytes(bytes, |frame| decoder.process_frame(frame))?;

    Ok(finish(&decoder, capture, settings))
}

fn finish(decoder: &Decoder, capture: CaptureStats, settings: &ExportSettings) -> DecodeOutcome {
    let good = decoder.export(settings);
    let decode = decoder.stats();

    DecodeOutcome {
        warnings: warnings(&capture, &decode),
        good,
        capture,
        decode,
    }
}

fn warnings(capture: &CaptureStats, decode: &DecodeStats) -> Vec<Warning> {
    if decode.item_packets != 0 || decode.avatar_packets != 0 {
        return Vec::new();
    }

    if decode.handshakes == 0 {
        vec![Warning::new(
            "no connection handshake was found in the capture",
            "start capturing before launching the game",
        )]
    } else if decode.compressed_commands > 0 {
        vec![Warning::new(
            "the game compressed its login response (Oodle Network TCP), which this decoder \
             cannot decompress",
            "the session key could not be derived; re-capture the session (the login response \
             is not always compressed)",
        )]
    } else if capture.game_packets > 20 && decode.commands.saturating_mul(10) < capture.game_packets
    {
        vec![Warning::new(
            format!(
                "only {} commands could be decrypted from {} game packets, so the session key \
                 was not established",
                decode.commands, capture.game_packets
            ),
            "the login response likely uses a format this decoder does not support yet (see the \
             README)",
        )]
    } else {
        vec![Warning::new(
            "the capture contains no character or inventory data",
            "the game may not have sent its inventory during the capture",
        )]
    }
}
