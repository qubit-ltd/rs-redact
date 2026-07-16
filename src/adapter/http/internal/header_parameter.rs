// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unambiguous HTTP header parameter parsing.

/// Result of looking up one semicolon-separated header parameter.
#[must_use]
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
    /// Unrequested parameters without a value are ignored. A requested
    /// parameter without `=`, malformed quoting or line breaks, and repeated
    /// requested parameters are invalid.
    ///
    /// # Parameters
    ///
    /// * `value` - Header value containing semicolon-separated parameters.
    /// * `parameter_name` - Parameter name to find case-insensitively.
    ///
    /// # Returns
    ///
    /// Parsed parameter state.
    #[inline]
    pub(in crate::adapter::http) fn parse(
        value: &str,
        parameter_name: &str,
    ) -> Self {
        let Some([parameter]) =
            parse_header_parameters(value, [parameter_name])
        else {
            return Self::Invalid;
        };
        match parameter {
            Some(parameter) => Self::Value(parameter),
            None => Self::Absent,
        }
    }
}

/// Parses several semicolon-separated header parameters in one pass.
///
/// Unrequested parameters without a value are ignored. A requested parameter
/// without `=`, malformed quoting or line breaks, and repeated requested
/// parameters are invalid.
///
/// # Parameters
///
/// * `value` - Header value containing semicolon-separated parameters.
/// * `parameter_names` - Parameter names to find case-insensitively.
///
/// # Returns
///
/// One optional decoded value per requested name, or `None` when the header is
/// malformed or any requested parameter is duplicated.
pub(in crate::adapter::http) fn parse_header_parameters<const N: usize>(
    value: &str,
    parameter_names: [&str; N],
) -> Option<[Option<String>; N]> {
    if value.contains(['\r', '\n']) {
        return None;
    }
    let segments = header_parameter_segments(value)?;
    let mut result = std::array::from_fn(|_| None);
    for segment in segments.into_iter().skip(1) {
        let Some((name, raw_value)) = segment.split_once('=') else {
            if parameter_names.iter().any(|parameter_name| {
                segment.trim().eq_ignore_ascii_case(parameter_name)
            }) {
                return None;
            }
            continue;
        };
        let Some(index) = parameter_names.iter().position(|parameter_name| {
            name.trim().eq_ignore_ascii_case(parameter_name)
        }) else {
            continue;
        };
        if result[index].is_some() {
            return None;
        }
        result[index] = Some(decode_header_parameter(raw_value.trim())?);
    }
    Some(result)
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
