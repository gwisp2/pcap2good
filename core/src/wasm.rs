//! wasm-bindgen entry points for the browser wrapper.

use wasm_bindgen::prelude::*;

use crate::api::decode_capture_bytes;

/// Decodes a `.pcap` or `.pcapng` capture held in memory.
///
/// Returns a JSON report of the shape
/// `{ "good": { ... }, "capture": { ... }, "decode": { ... }, "warnings": [ ... ] }`.
#[wasm_bindgen]
pub fn decode(bytes: &[u8]) -> Result<String, JsValue> {
    let outcome = decode_capture_bytes(bytes, None)
        .map_err(|error| JsValue::from_str(&format!("{error:#}")))?;

    serde_json::to_string(&outcome)
        .map_err(|error| JsValue::from_str(&format!("failed to encode the result: {error}")))
}
