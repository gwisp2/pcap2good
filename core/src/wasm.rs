//! wasm-bindgen entry points for the browser wrapper.

use wasm_bindgen::prelude::*;

use crate::api::decode_capture_bytes;
use crate::player_data::ExportSettings;

/// Decodes a `.pcap` or `.pcapng` capture held in memory.
///
/// `options_json` is an optional JSON object with [`ExportSettings`] fields
/// (for example `{"fakeInitialize4thLine":true}`).
///
/// Returns a JSON report of the shape
/// `{ "good": { ... }, "capture": { ... }, "decode": { ... }, "warnings": [ ... ] }`.
#[wasm_bindgen]
pub fn decode(bytes: &[u8], options_json: Option<String>) -> Result<String, JsValue> {
    let settings = parse_settings(options_json.as_deref())?;
    let outcome = decode_capture_bytes(bytes, &settings, None)
        .map_err(|error| JsValue::from_str(&format!("{error:#}")))?;

    serde_json::to_string(&outcome)
        .map_err(|error| JsValue::from_str(&format!("failed to encode the result: {error}")))
}

fn parse_settings(json: Option<&str>) -> Result<ExportSettings, JsValue> {
    match json {
        Some(json) if !json.trim().is_empty() => serde_json::from_str(json)
            .map_err(|error| JsValue::from_str(&format!("invalid options: {error}"))),
        _ => Ok(ExportSettings::default()),
    }
}
