//! Schema-less protobuf decoding for `--dump-commands`.
//!
//! Command dumps carry raw protobuf without its `.proto` schema, so the JSON
//! mirrors the wire format: object keys are field numbers (as strings) and
//! values are the decoded wire values.

use std::collections::BTreeMap;

use base64::prelude::*;
use serde_json::{Map, Value};

/// Decodes a protobuf message without a schema.
///
/// Returns `None` when `bytes` is not a well-formed protobuf message. Fields
/// that occur more than once are collected into arrays. Length-delimited
/// fields are decoded as nested messages when possible, otherwise as UTF-8
/// strings, otherwise as base64.
pub fn decode_message(bytes: &[u8]) -> Option<Value> {
    let mut fields: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
    let mut rest = bytes;

    while !rest.is_empty() {
        let (key, used) = read_varint(rest)?;
        rest = rest.get(used..)?;

        let field = key >> 3;
        if field == 0 {
            return None;
        }

        let value = match key & 7 {
            // Varint.
            0 => {
                let (value, used) = read_varint(rest)?;
                rest = rest.get(used..)?;
                Value::from(value)
            }
            // Fixed 64 bit.
            1 => {
                let value = u64::from_le_bytes(rest.get(..8)?.try_into().ok()?);
                rest = rest.get(8..)?;
                Value::from(value)
            }
            // Length delimited.
            2 => {
                let (len, used) = read_varint(rest)?;
                rest = rest.get(used..)?;
                let len = usize::try_from(len).ok()?;
                let value = rest.get(..len)?;
                rest = rest.get(len..)?;
                length_delimited(value)
            }
            // Fixed 32 bit.
            5 => {
                let value = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
                rest = rest.get(4..)?;
                Value::from(value)
            }
            // Groups (3, 4) are deprecated and unused by the game; 6 and 7 are
            // not valid wire types.
            _ => return None,
        };

        fields.entry(field).or_default().push(value);
    }

    Some(into_object(fields))
}

/// Like [`decode_message`], but falls back to base64 instead of failing so
/// that malformed or truncated data is still visible in the dump.
pub fn decode_or_base64(bytes: &[u8]) -> Value {
    decode_message(bytes).unwrap_or_else(|| Value::from(BASE64_STANDARD.encode(bytes)))
}

/// Decodes a length-delimited value, which may hold a nested message, a string
/// or arbitrary bytes.
fn length_delimited(bytes: &[u8]) -> Value {
    // Text is checked first: short ASCII strings such as "hi" are also valid
    // protobuf (field 13, varint 105), so decoding first would mistake them
    // for messages. Control characters never appear in text fields but are
    // common in the field keys of nested messages.
    if let Ok(text) = std::str::from_utf8(bytes)
        && !text.chars().any(char::is_control)
    {
        return Value::from(text);
    }

    if let Some(message) = decode_message(bytes) {
        return message;
    }

    match std::str::from_utf8(bytes) {
        Ok(text) => Value::from(text),
        Err(_) => Value::from(BASE64_STANDARD.encode(bytes)),
    }
}

fn into_object(fields: BTreeMap<u64, Vec<Value>>) -> Value {
    let mut object = Map::new();

    for (field, mut values) in fields {
        let value = if values.len() == 1 {
            values.pop().expect("exactly one value")
        } else {
            Value::Array(values)
        };
        object.insert(field.to_string(), value);
    }

    Value::Object(object)
}

/// Reads an unsigned varint from the start of `bytes`.
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;

    for (index, byte) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decodes_scalar_fields() {
        // field 1 = 150, field 2 = "hi", field 3 = 1.0 (fixed32)
        let bytes = [
            0x08, 0x96, 0x01, 0x12, 0x02, b'h', b'i', 0x1d, 0, 0, 0x80, 0x3f,
        ];
        assert_eq!(
            decode_message(&bytes),
            Some(json!({ "1": 150, "2": "hi", "3": 1065353216 }))
        );
    }

    #[test]
    fn decodes_nested_messages() {
        // field 1 = { field 2 = 7 }
        let bytes = [0x0a, 0x02, 0x10, 0x07];
        assert_eq!(decode_message(&bytes), Some(json!({ "1": { "2": 7 } })));
    }

    #[test]
    fn collects_repeated_fields_into_arrays() {
        // field 1 = 1, field 1 = 2, field 1 = 3
        let bytes = [0x08, 0x01, 0x08, 0x02, 0x08, 0x03];
        assert_eq!(decode_message(&bytes), Some(json!({ "1": [1, 2, 3] })));
    }

    #[test]
    fn empty_message_is_an_empty_object() {
        assert_eq!(decode_message(&[]), Some(json!({})));
    }

    #[test]
    fn keeps_binary_data_as_base64() {
        // field 1 = [0xff, 0x00, 0xff] is neither a message nor UTF-8.
        let bytes = [0x0a, 0x03, 0xff, 0x00, 0xff];
        assert_eq!(decode_message(&bytes), Some(json!({ "1": "/wD/" })));
    }

    #[test]
    fn rejects_invalid_wire_types() {
        // field 1 with wire type 6.
        assert_eq!(decode_message(&[0x0e, 0x00]), None);
    }

    #[test]
    fn rejects_truncated_input() {
        // field 1 with a two-byte length but only one byte of data.
        assert_eq!(decode_message(&[0x0a, 0x02, 0x00]), None);
    }

    #[test]
    fn falls_back_to_base64_for_undecodable_data() {
        assert_eq!(decode_or_base64(&[0x0e, 0x00]), json!("DgA="));
    }
}
