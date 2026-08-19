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
use serde_json::from_str;
use serde_json::to_writer;

use super::BoundedBodyWriter;
use super::markers::UNKEYED_JSON;
use crate::formats::http::FieldRedactor;
use crate::formats::http::UnkeyedJsonValuePolicy;
use crate::formats::json::internal::JsonRedactionState;
use crate::formats::json::internal::JsonUnkeyedValuePolicy;

/// Redacts a JSON tree and reports whether an unkeyed scalar passed through.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `value` - JSON tree to mutate.
/// * `unkeyed` - Policy for scalars without an object-field context.
/// # Returns
///
/// `true` when at least one unkeyed scalar passed through.
#[must_use]
pub(in crate::formats::http) fn redact(
    redactor: &FieldRedactor<'_>,
    value: &mut Value,
    unkeyed: UnkeyedJsonValuePolicy,
) -> bool {
    let unkeyed = match unkeyed {
        UnkeyedJsonValuePolicy::PassThrough => JsonUnkeyedValuePolicy::PassThrough,
        UnkeyedJsonValuePolicy::Redact => JsonUnkeyedValuePolicy::Redact { marker: UNKEYED_JSON },
    };
    let outcome = JsonRedactionState::new(
        redactor.base_rules(),
        redactor.context_rules(),
        redactor.masking(),
        unkeyed,
    )
    .redact(value);
    match outcome {
        crate::formats::json::internal::JsonRedactionOutcome::Complete { passed_unkeyed } => passed_unkeyed,
    }
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
pub(in crate::formats::http) fn serialize_bounded(value: &Value, max_output_bytes: usize) -> Option<(String, bool)> {
    let mut writer = BoundedBodyWriter::new(max_output_bytes);
    if to_writer(&mut writer, value).is_err() {
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
/// * `max_output_bytes` - Maximum final rendered NDJSON bytes.
///
/// # Returns
///
/// Redacted NDJSON, a pass-through flag, and a rendering-truncation flag, or
/// `None` for invalid input.
#[must_use]
pub(in crate::formats::http) fn redact_ndjson(
    redactor: &FieldRedactor<'_>,
    bytes: &[u8],
    unkeyed: UnkeyedJsonValuePolicy,
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
        let mut value = from_str(line).ok()?;
        let line_passed = redact(redactor, &mut value, unkeyed);
        passed |= line_passed;
        if to_writer(&mut output, &value).is_err() {
            return output.into_string().map(|text| (text, passed, true));
        }
    }
    if trailing_newline && output.write_all(b"\n").is_err() {
        return output.into_string().map(|text| (text, passed, true));
    }
    output.into_string().map(|text| (text, passed, false))
}
