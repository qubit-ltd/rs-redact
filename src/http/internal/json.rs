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

use crate::json::internal::{
    JsonRedactionState,
    JsonUnkeyedValuePolicy,
};

use crate::{
    JsonDepthBudget,
    http::{
        FieldRedactor,
        UnkeyedJsonValuePolicy,
    },
};

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
    redactor: &FieldRedactor<'_>,
    value: &mut Value,
    json_depth_budget: JsonDepthBudget,
    unkeyed: UnkeyedJsonValuePolicy,
    max_mask_bytes: usize,
) -> bool {
    let mut remaining_mask_bytes = max_mask_bytes;
    redact_with_remaining(
        redactor,
        value,
        json_depth_budget,
        unkeyed,
        &mut remaining_mask_bytes,
    )
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
    redactor: &FieldRedactor<'_>,
    value: &mut Value,
    json_depth_budget: JsonDepthBudget,
    unkeyed: UnkeyedJsonValuePolicy,
    remaining_mask_bytes: &mut usize,
) -> bool {
    let unkeyed = match unkeyed {
        UnkeyedJsonValuePolicy::PassThrough => {
            JsonUnkeyedValuePolicy::PassThrough
        }
        UnkeyedJsonValuePolicy::Redact => JsonUnkeyedValuePolicy::Redact {
            marker: UNKEYED_JSON,
            truncated_marker: TRUNCATED,
        },
    };
    JsonRedactionState::new(
        redactor.rules(),
        redactor.masking(),
        json_depth_budget,
        unkeyed,
        remaining_mask_bytes,
    )
    .redact(value)
    .has_passed_unkeyed()
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
/// serialization exceeded the output budget, or `None` for UTF-8 errors.
#[must_use]
pub(in crate::http) fn serialize_bounded(
    value: &Value,
    max_output_bytes: usize,
) -> Option<(String, bool)> {
    let mut writer = BoundedBodyWriter::new(max_output_bytes);
    if serde_json::to_writer(&mut writer, value).is_err() {
        return writer.into_string().map(|text| (text, true));
    }
    writer.flush().ok()?;
    writer.into_string().map(|text| (text, false))
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
    redactor: &FieldRedactor<'_>,
    bytes: &[u8],
    json_depth_budget: JsonDepthBudget,
    unkeyed: UnkeyedJsonValuePolicy,
    max_mask_bytes: usize,
) -> Option<(String, bool, bool)> {
    let mut remaining_mask_bytes = max_mask_bytes;
    redact_ndjson_with_remaining(
        redactor,
        bytes,
        json_depth_budget,
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
/// `None` for invalid UTF-8 or JSON.
#[must_use]
pub(in crate::http) fn redact_ndjson_with_remaining(
    redactor: &FieldRedactor<'_>,
    bytes: &[u8],
    json_depth_budget: JsonDepthBudget,
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
            json_depth_budget,
            unkeyed,
            remaining_mask_bytes,
        );
        if serde_json::to_writer(&mut output, &value).is_err() {
            return output.into_string().map(|text| (text, passed, true));
        }
    }
    if trailing_newline && output.write_all(b"\n").is_err() {
        return output.into_string().map(|text| (text, passed, true));
    }
    output.into_string().map(|text| (text, passed, false))
}
