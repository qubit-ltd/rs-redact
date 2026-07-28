// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! JSON tree redaction and bounded rendering.

use std::io::Write;

use serde_json::Value;

use crate::Redactor;

use crate::http::UnkeyedJsonValuePolicy;

use super::{
    BoundedBodyWriter,
    markers::{
        TRUNCATED,
        UNKEYED_JSON,
    },
};

/// Redacts a JSON tree and reports whether an unkeyed scalar passed through.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `value` - JSON tree to mutate.
/// * `unkeyed` - Policy for scalars without an object-field context.
/// * `max_mask_bytes` - Aggregate bytes allocated for generated masks.
///
/// # Returns
///
/// `true` when at least one unkeyed scalar passed through.
#[must_use]
pub(in crate::http) fn redact(
    redactor: &Redactor,
    value: &mut Value,
    unkeyed: UnkeyedJsonValuePolicy,
    max_mask_bytes: usize,
) -> bool {
    let mut remaining_mask_bytes = max_mask_bytes;
    redact_with_remaining(redactor, value, unkeyed, &mut remaining_mask_bytes)
}

/// Redacts a JSON tree while consuming one enclosing mask budget.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `value` - JSON tree to mutate.
/// * `unkeyed` - Policy for scalars without an object-field context.
/// * `remaining_mask_bytes` - Aggregate mask bytes still available to the
///   enclosing body renderer.
///
/// # Returns
///
/// `true` when at least one unkeyed scalar passed through.
#[must_use]
pub(in crate::http) fn redact_with_remaining(
    redactor: &Redactor,
    value: &mut Value,
    unkeyed: UnkeyedJsonValuePolicy,
    remaining_mask_bytes: &mut usize,
) -> bool {
    redact_with_context(redactor, value, unkeyed, remaining_mask_bytes, false)
}

/// Serializes a redacted JSON value without exceeding the rendered-body limit.
///
/// # Parameters
///
/// * `value` - Redacted JSON tree to serialize.
/// * `max_output_bytes` - Maximum rendered JSON bytes to retain.
///
/// # Returns
///
/// `Some((text, false))` for complete JSON, `Some((prefix, true))` when
/// serialization exceeded the output budget, or `None` for serialization or
/// UTF-8 errors.
#[must_use]
pub(in crate::http) fn serialize_bounded(
    value: &Value,
    max_output_bytes: usize,
) -> Option<(String, bool)> {
    let mut writer = BoundedBodyWriter::new(max_output_bytes);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => writer.into_string().map(|text| (text, false)),
        Err(_) if writer.overflowed() => {
            writer.into_string().map(|text| (text, true))
        }
        Err(_) => None,
    }
}

/// Redacts every non-empty line of one NDJSON document.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `bytes` - Complete NDJSON bytes.
/// * `unkeyed` - Policy for unkeyed scalar values.
/// * `max_mask_bytes` - Aggregate bytes allocated for generated masks and
///   rendered NDJSON output.
///
/// # Returns
///
/// Redacted NDJSON, a pass-through flag, and a rendering-truncation flag, or
/// `None` for invalid input.
#[must_use]
pub(in crate::http) fn redact_ndjson(
    redactor: &Redactor,
    bytes: &[u8],
    unkeyed: UnkeyedJsonValuePolicy,
    max_mask_bytes: usize,
) -> Option<(String, bool, bool)> {
    let mut remaining_mask_bytes = max_mask_bytes;
    redact_ndjson_with_remaining(
        redactor,
        bytes,
        unkeyed,
        &mut remaining_mask_bytes,
        max_mask_bytes,
    )
}

/// Redacts NDJSON while consuming an enclosing aggregate mask budget and
/// enforcing a final rendered-output limit.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `bytes` - Complete NDJSON bytes.
/// * `unkeyed` - Policy for unkeyed scalar values.
/// * `remaining_mask_bytes` - Aggregate generated-mask budget shared with an
///   enclosing renderer.
/// * `max_output_bytes` - Maximum rendered NDJSON bytes to retain.
///
/// # Returns
///
/// Redacted NDJSON, a pass-through flag, and a rendering-truncation flag, or
/// `None` for invalid UTF-8, JSON, or serialization.
#[must_use]
pub(in crate::http) fn redact_ndjson_with_remaining(
    redactor: &Redactor,
    bytes: &[u8],
    unkeyed: UnkeyedJsonValuePolicy,
    remaining_mask_bytes: &mut usize,
    max_output_bytes: usize,
) -> Option<(String, bool, bool)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let trailing_newline = text.ends_with('\n');
    let mut output = BoundedBodyWriter::new(max_output_bytes);
    let mut needs_separator = false;
    let mut passed = false;
    for line in text.lines() {
        if needs_separator && output.write_all(b"\n").is_err() {
            return output.into_string().map(|text| (text, passed, true));
        }
        needs_separator = true;
        if line.trim().is_empty() {
            continue;
        }
        let mut value = serde_json::from_str(line).ok()?;
        passed |= redact_with_remaining(
            redactor,
            &mut value,
            unkeyed,
            remaining_mask_bytes,
        );
        if serde_json::to_writer(&mut output, &value).is_err() {
            if output.overflowed() {
                return output
                    .into_string()
                    .map(|text| (text, passed, true));
            }
            return None;
        }
    }
    if trailing_newline && output.write_all(b"\n").is_err() {
        return output.into_string().map(|text| (text, passed, true));
    }
    output.into_string().map(|text| (text, passed, false))
}

/// Redacts one JSON node with its object-field context.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `value` - Current JSON node.
/// * `unkeyed` - Policy for unkeyed scalar values.
/// * `remaining_mask_bytes` - Aggregate bytes still available for generated
///   masks in the enclosing document.
/// * `has_field` - Whether an object key identifies this node.
///
/// # Returns
///
/// `true` when this subtree passed through an unkeyed scalar.
#[must_use]
fn redact_with_context(
    redactor: &Redactor,
    value: &mut Value,
    unkeyed: UnkeyedJsonValuePolicy,
    remaining_mask_bytes: &mut usize,
    has_field: bool,
) -> bool {
    match value {
        Value::Object(map) => {
            let mut passed = false;
            for (key, value) in map {
                if let Some(level) = redactor.policy().sensitivity_for(key) {
                    let masked = if let Value::String(text) = value {
                        redactor
                            .policy()
                            .masking()
                            .mask_bounded(level, text, *remaining_mask_bytes)
                            .into_owned()
                    } else {
                        redactor
                            .policy()
                            .masking()
                            .mask_opaque_bounded(level, *remaining_mask_bytes)
                    };
                    *remaining_mask_bytes =
                        remaining_mask_bytes.saturating_sub(masked.len());
                    *value = Value::String(masked);
                } else {
                    passed |= redact_with_context(
                        redactor,
                        value,
                        unkeyed,
                        remaining_mask_bytes,
                        true,
                    );
                }
            }
            passed
        }
        Value::Array(values) => {
            let mut passed = false;
            for value in values {
                passed |= redact_with_context(
                    redactor,
                    value,
                    unkeyed,
                    remaining_mask_bytes,
                    has_field,
                );
            }
            passed
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
            if !has_field =>
        {
            match unkeyed {
                UnkeyedJsonValuePolicy::Redact => {
                    *value = Value::String(take_unkeyed_marker(
                        remaining_mask_bytes,
                    ));
                    false
                }
                UnkeyedJsonValuePolicy::PassThrough => true,
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            false
        }
    }
}

/// Consumes the remaining generated-mask budget for one unkeyed JSON marker.
///
/// # Parameters
///
/// * `remaining_mask_bytes` - Aggregate bytes available for generated masks.
///
/// # Returns
///
/// The full unkeyed marker when it fits, the shorter truncation marker when it
/// fits, or an empty JSON string when no marker can fit safely.
fn take_unkeyed_marker(remaining_mask_bytes: &mut usize) -> String {
    let marker = if *remaining_mask_bytes >= UNKEYED_JSON.len() {
        UNKEYED_JSON
    } else if *remaining_mask_bytes >= TRUNCATED.len() {
        TRUNCATED
    } else {
        return String::new();
    };
    *remaining_mask_bytes = remaining_mask_bytes.saturating_sub(marker.len());
    marker.to_string()
}
