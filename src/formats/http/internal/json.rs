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
use serde_json::to_writer;

use super::AdmittedNdjson;
use super::BoundedBodyWriter;
use super::markers::UNKEYED_JSON;
use crate::UnkeyedJsonValuePolicy;
use crate::formats::http::FieldRedactor;
use crate::formats::json::internal::JsonRedactionState;
use crate::formats::json::internal::JsonUnkeyedValuePolicy;

/// Reports whether an NDJSON line contains only Unicode whitespace.
#[must_use]
#[inline]
pub(in crate::formats::http) fn is_blank_ndjson_line(line: &str) -> bool {
    line.trim().is_empty()
}

/// Redacts one admitted JSON value directly into a bounded writer.
///
/// # Returns
///
/// The borrowed output's pass-through and truncation status.
pub(in crate::formats::http) fn redact_and_serialize_bounded(
    redactor: &FieldRedactor<'_>,
    value: &Value,
    unkeyed: UnkeyedJsonValuePolicy,
    max_output_bytes: usize,
) -> Option<(String, bool, bool)> {
    let mut output = BoundedBodyWriter::new(max_output_bytes);
    let state = state(redactor, unkeyed);
    let failed = to_writer(&mut output, &state.redact(value)).is_err();
    output.flush().ok()?;
    let text = output.into_string()?;
    Some((text, passed(&state), failed))
}

/// Redacts already admitted NDJSON values without parsing their source again.
///
/// # Returns
///
/// Redacted NDJSON, a pass-through flag, and a rendering-truncation flag, or
/// `None` if the bounded writer cannot produce UTF-8 text.
pub(in crate::formats::http) fn redact_ndjson_values(
    redactor: &FieldRedactor<'_>,
    lines: &mut AdmittedNdjson,
    unkeyed: UnkeyedJsonValuePolicy,
    max_output_bytes: usize,
) -> Option<(String, bool, bool)> {
    let mut output = BoundedBodyWriter::new(max_output_bytes);
    let mut passed_any = false;
    let line_count = lines.line_count();
    let trailing_newline = lines.trailing_newline();
    let mut cursor = 0;
    for (source_index, value) in lines.records_mut() {
        while cursor < *source_index {
            if cursor > 0 && output.write_all(b"\n").is_err() {
                return Some((output.into_string()?, passed_any, true));
            }
            cursor += 1;
        }
        if cursor > 0 && output.write_all(b"\n").is_err() {
            return Some((output.into_string()?, passed_any, true));
        }
        let state = state(redactor, unkeyed);
        if to_writer(&mut output, &state.redact(value)).is_err() {
            return Some((output.into_string()?, passed_any | passed(&state), true));
        }
        passed_any |= passed(&state);
        cursor += 1;
    }
    while cursor < line_count {
        if cursor > 0 && output.write_all(b"\n").is_err() {
            return Some((output.into_string()?, passed_any, true));
        }
        cursor += 1;
    }
    if trailing_newline && output.write_all(b"\n").is_err() {
        return Some((output.into_string()?, passed_any, true));
    }
    Some((output.into_string()?, passed_any, false))
}

fn state<'a>(redactor: &'a FieldRedactor<'_>, unkeyed: UnkeyedJsonValuePolicy) -> JsonRedactionState<'a, 'static> {
    let unkeyed = match unkeyed {
        UnkeyedJsonValuePolicy::PassThrough => JsonUnkeyedValuePolicy::PassThrough,
        UnkeyedJsonValuePolicy::Redact => JsonUnkeyedValuePolicy::Redact { marker: UNKEYED_JSON },
    };
    JsonRedactionState::new(
        redactor.base_rules(),
        redactor.context_rules(),
        redactor.masking(),
        unkeyed,
        true,
    )
}

fn passed(state: &JsonRedactionState<'_, '_>) -> bool {
    match state.outcome() {
        crate::formats::json::internal::JsonRedactionOutcome::Complete { passed_unkeyed } => passed_unkeyed,
    }
}
