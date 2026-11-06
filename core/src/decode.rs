//! Builds the packet pipeline and exposes the high-level decoder.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::prelude::*;
use flate2::read::GzDecoder;
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};

use crate::capture::CaptureStats;
use crate::gamedata::GameData;
use crate::pipeline::sink::{DefaultFlowSinkFactory, DumpState};
use crate::pipeline::{CapturedFrame, Pipeline, SharedContext};

static DATABASE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/game_data.gz"));

pub use crate::pipeline::{DecodeResult, DecodeSnapshot, DecodeStats};

pub struct Decoder {
    pipeline: Pipeline,
}

impl Decoder {
    /// Creates a decoder without writing decoded commands anywhere.
    pub fn new() -> Result<Self> {
        Self::with_command_dump(None)
    }

    /// Creates a decoder. When `dump_dir` is set, every decoded command is
    /// written there as `.bin` and `.json`.
    pub fn with_command_dump(dump_dir: Option<PathBuf>) -> Result<Self> {
        let game_data = Arc::new(
            GameData::from_reader(GzDecoder::new(DATABASE))
                .context("Failed to load the embedded game data")?,
        );

        let dump = match dump_dir {
            Some(dir) => {
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("Failed to create {}", dir.display()))?;
                Some(Arc::new(Mutex::new(DumpState { dir, counter: 0 })))
            }
            None => None,
        };

        let shared = Arc::new(SharedContext {
            game_data,
            initial_keys: Arc::new(load_keys()?),
            rsa_keys: Arc::new(load_rsa_keys()),
        });
        let sink_factory = Arc::new(DefaultFlowSinkFactory { dump });

        Ok(Self {
            pipeline: Pipeline::new(shared, sink_factory),
        })
    }

    pub fn process_frame(&mut self, frame: CapturedFrame) {
        self.pipeline.process_frame(frame);
    }

    /// Returns statistics and decoded data without ending the session.
    pub fn snapshot(&self) -> DecodeSnapshot {
        self.pipeline.snapshot()
    }

    pub fn finish(self, capture: CaptureStats) -> DecodeResult {
        self.pipeline.finish(capture)
    }
}

fn load_keys() -> Result<HashMap<u16, Vec<u8>>> {
    let keys: HashMap<u16, String> = serde_json::from_slice(include_bytes!("../keys/gi.json"))
        .context("Failed to parse keys")?;

    keys.iter()
        .map(|(key, value)| -> Result<_, _> { Ok((*key, BASE64_STANDARD.decode(value)?)) })
        .collect::<Result<HashMap<_, _>>>()
}

fn load_rsa_keys() -> Vec<RsaPrivateKey> {
    let pem_data_4 = include_str!("auto_artifactarium/keys/private_key_4.pem");
    let pem_data_5 = include_str!("auto_artifactarium/keys/private_key_5.pem");

    [pem_data_4, pem_data_5]
        .iter()
        .filter_map(|pem| RsaPrivateKey::from_pkcs1_pem(pem).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_keys_load() {
        assert!(!load_keys().unwrap().is_empty());
        assert!(!load_rsa_keys().is_empty());
    }
}
