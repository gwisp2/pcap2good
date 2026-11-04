//! Low-level pieces copied from [`auto-artifactarium`](https://github.com/konkers/auto-artifactarium).
//!
//! This module keeps the generated protobuf types and the small cryptographic
//! helpers that the capture pipeline needs. Packet orchestration, KCP
//! reassembly, command framing and player-data matching live in
//! [`crate::pipeline`] instead.
//!
//! Upstream revision `abbbf7a3f58846512250a789a76be2d3cdb115c1` (v1.4.0) is the
//! base.

use std::fmt::Write;

pub mod r#gen;

pub(crate) mod crypto;
pub(crate) mod cs_rand;
#[allow(dead_code)]
#[allow(clippy::all)]
pub(crate) mod unk_util;

fn bytes_as_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}
