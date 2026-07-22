// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! JSON tree redaction.

use serde_json::Value;

use crate::Redactor;

use super::markers::UNKEYED_JSON;
use crate::http::UnkeyedJsonValuePolicy;

/// Redacts a JSON tree and reports whether an unkeyed scalar passed through.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `value` - JSON tree to mutate.
/// * `unkeyed` - Policy for scalars without an object-field context.
/// * `max_mask_bytes` - Maximum bytes allocated for one generated mask.
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
    redact_with_context(redactor, value, unkeyed, max_mask_bytes, false)
}

/// Redacts every non-empty line of one NDJSON document.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `bytes` - Complete NDJSON bytes.
/// * `unkeyed` - Policy for unkeyed scalar values.
/// * `max_mask_bytes` - Maximum bytes allocated for one generated mask.
///
/// # Returns
///
/// Redacted NDJSON and a pass-through flag, or `None` for invalid input.
#[must_use]
pub(in crate::http) fn redact_ndjson(
    redactor: &Redactor,
    bytes: &[u8],
    unkeyed: UnkeyedJsonValuePolicy,
    max_mask_bytes: usize,
) -> Option<(String, bool)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let trailing_newline = text.ends_with('\n');
    let mut lines = Vec::new();
    let mut passed = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut value = serde_json::from_str(line).ok()?;
        passed |= redact(redactor, &mut value, unkeyed, max_mask_bytes);
        lines.push(serde_json::to_string(&value).ok()?);
    }
    let mut output = lines.join("\n");
    if trailing_newline {
        output.push('\n');
    }
    Some((output, passed))
}

/// Redacts one JSON node with its object-field context.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `value` - Current JSON node.
/// * `unkeyed` - Policy for unkeyed scalar values.
/// * `max_mask_bytes` - Maximum bytes allocated for one generated mask.
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
    max_mask_bytes: usize,
    has_field: bool,
) -> bool {
    match value {
        Value::Object(map) => {
            let mut passed = false;
            for (key, value) in map {
                if let Some(level) = redactor.policy().sensitivity_for(key) {
                    let serialized;
                    let input = if let Value::String(text) = value {
                        text.as_str()
                    } else {
                        serialized = value.to_string();
                        &serialized
                    };
                    *value = Value::String(
                        redactor
                            .policy()
                            .masking()
                            .mask_bounded(level, input, max_mask_bytes)
                            .into_owned(),
                    );
                } else {
                    passed |= redact_with_context(
                        redactor,
                        value,
                        unkeyed,
                        max_mask_bytes,
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
                    max_mask_bytes,
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
                    *value = Value::String(UNKEYED_JSON.to_string());
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
