// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unambiguous HTTP header parameter parsing.

/// Result of looking up one semicolon-separated header parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::adapter::http) enum HeaderParameter {
    /// The requested parameter was not present.
    Absent,
    /// The requested parameter occurred exactly once with a valid value.
    Value(String),
    /// The header was malformed or the requested parameter was duplicated.
    Invalid,
}

impl HeaderParameter {
    /// Parses one semicolon-separated header parameter without ambiguity.
    ///
    /// Parameters without a value are ignored unless quoting or line breaks
    /// make the complete header malformed. A repeated requested parameter is
    /// invalid even when both values are identical.
    ///
    /// # Parameters
    ///
    /// * `value` - Header value containing semicolon-separated parameters.
    /// * `parameter_name` - Parameter name to find case-insensitively.
    ///
    /// # Returns
    ///
    /// Parsed parameter state.
    pub(in crate::adapter::http) fn parse(
        value: &str,
        parameter_name: &str,
    ) -> Self {
        if value.contains(['\r', '\n']) {
            return Self::Invalid;
        }
        let Some(segments) = header_parameter_segments(value) else {
            return Self::Invalid;
        };
        let mut result = Self::Absent;
        for segment in segments.into_iter().skip(1) {
            let Some((name, raw_value)) = segment.split_once('=') else {
                continue;
            };
            if !name.trim().eq_ignore_ascii_case(parameter_name) {
                continue;
            }
            if result != Self::Absent {
                return Self::Invalid;
            }
            let Some(decoded) = decode_header_parameter(raw_value.trim())
            else {
                return Self::Invalid;
            };
            result = Self::Value(decoded);
        }
        result
    }
}

/// Splits header parameters while respecting quoted semicolons.
///
/// # Parameters
///
/// * `value` - Header value containing parameters.
///
/// # Returns
///
/// Parameter segments, or `None` when quoting is malformed.
fn header_parameter_segments(value: &str) -> Option<Vec<&str>> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_quote && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quote = !in_quote;
            continue;
        }
        if ch == ';' && !in_quote {
            segments.push(value[start..index].trim());
            start = index + ch.len_utf8();
        }
    }
    if in_quote || escaped {
        return None;
    }
    segments.push(value[start..].trim());
    Some(segments)
}

/// Decodes a simple HTTP header parameter value.
///
/// # Parameters
///
/// * `value` - Raw parameter value.
///
/// # Returns
///
/// Unquoted value, or `None` for malformed quoted strings.
fn decode_header_parameter(value: &str) -> Option<String> {
    if !value.starts_with('"') {
        if value.contains('"') {
            return None;
        }
        return Some(value.trim().to_string());
    }
    if !value.ends_with('"') || value.len() < 2 {
        return None;
    }
    let mut result = String::new();
    let mut chars = value[1..value.len() - 1].chars();
    while let Some(ch) = chars.next() {
        let value = if ch == '\\' { chars.next()? } else { ch };
        if value == '\r' || value == '\n' {
            return None;
        }
        result.push(value);
    }
    Some(result)
}
