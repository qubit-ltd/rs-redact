// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Minimal Content-Type classification.

use super::header_parameter::{
    is_token_byte,
    leading_value,
    parse_parameters,
};

/// Returns the normalized media-type portion.
///
/// # Parameters
///
/// * `value` - Complete Content-Type text.
///
/// # Returns
///
/// Trimmed text before the first semicolon.
#[must_use]
#[inline(always)]
fn media_type(value: &str) -> &str {
    leading_value(value).unwrap_or_default()
}

/// Reports whether a complete Content-Type has strict media-type grammar.
///
/// # Parameters
///
/// * `value` - Complete Content-Type text.
///
/// # Returns
///
/// `true` when the leading value is exactly `token/token` and every parameter
/// has valid, unique header-parameter grammar.
#[must_use]
pub(in crate::http) fn is_valid(value: &str) -> bool {
    let Some((kind, subtype)) = media_type(value).split_once('/') else {
        return false;
    };
    !kind.is_empty()
        && !subtype.is_empty()
        && kind.bytes().all(is_token_byte)
        && subtype.bytes().all(is_token_byte)
        && parse_parameters::<0>(value, []).is_some()
}

/// Reports whether the media type declares JSON.
///
/// # Parameters
///
/// * `value` - Complete Content-Type text.
///
/// # Returns
///
/// `true` for JSON media types and structured JSON suffixes.
#[must_use]
#[inline]
pub(in crate::http) fn is_json(value: &str) -> bool {
    let value = media_type(value).to_ascii_lowercase();
    value == "application/json"
        || value.ends_with("+json")
        || value.ends_with("/json")
}

/// Reports whether the media type declares NDJSON.
///
/// # Parameters
///
/// * `value` - Complete Content-Type text.
///
/// # Returns
///
/// `true` for either supported NDJSON media type.
#[must_use]
#[inline]
pub(in crate::http) fn is_ndjson(value: &str) -> bool {
    let value = media_type(value);
    value.eq_ignore_ascii_case("application/x-ndjson")
        || value.eq_ignore_ascii_case("application/ndjson")
}

/// Reports whether the media type declares a URL-encoded form.
///
/// # Parameters
///
/// * `value` - Complete Content-Type text.
///
/// # Returns
///
/// `true` for URL-encoded form data.
#[must_use]
#[inline(always)]
pub(in crate::http) fn is_form(value: &str) -> bool {
    media_type(value).eq_ignore_ascii_case("application/x-www-form-urlencoded")
}

/// Reports whether the media type declares multipart content.
///
/// # Parameters
///
/// * `value` - Complete Content-Type text.
///
/// # Returns
///
/// `true` for any multipart subtype.
#[must_use]
#[inline]
pub(in crate::http) fn is_multipart(value: &str) -> bool {
    media_type(value)
        .to_ascii_lowercase()
        .starts_with("multipart/")
}

/// Reports whether the media type is specifically multipart form data.
///
/// # Parameters
///
/// * `value` - Valid complete Content-Type text.
///
/// # Returns
///
/// `true` only for `multipart/form-data`, case-insensitively.
#[must_use]
#[inline(always)]
pub(in crate::http) fn is_multipart_form_data(value: &str) -> bool {
    media_type(value).eq_ignore_ascii_case("multipart/form-data")
}

/// Reports whether the media type declares opaque text.
///
/// # Parameters
///
/// * `value` - Complete Content-Type text.
///
/// # Returns
///
/// `true` for any text subtype.
#[must_use]
#[inline]
pub(in crate::http) fn is_text(value: &str) -> bool {
    media_type(value).to_ascii_lowercase().starts_with("text/")
}

/// Extracts a unique validated multipart boundary parameter.
///
/// # Parameters
///
/// * `value` - Multipart Content-Type text.
///
/// # Returns
///
/// The decoded conservative boundary, or `None` for invalid metadata.
#[must_use]
pub(in crate::http) fn multipart_boundary(value: &str) -> Option<String> {
    if !is_multipart(value) {
        return None;
    }
    let [boundary] = parse_parameters(value, ["boundary"])?;
    let boundary = boundary?;
    ((1..=70).contains(&boundary.len())
        && boundary.bytes().all(is_boundary_byte)
        && boundary
            .as_bytes()
            .last()
            .copied()
            .is_some_and(is_boundary_non_space_byte))
    .then_some(boundary)
}

/// Reports whether one byte is accepted in a conservative boundary.
///
/// # Parameters
///
/// * `byte` - Candidate ASCII byte.
///
/// # Returns
///
/// `true` when the byte is permitted in a boundary.
#[must_use]
#[inline]
const fn is_boundary_byte(byte: u8) -> bool {
    byte == b' ' || is_boundary_non_space_byte(byte)
}

/// Reports whether one byte is accepted at the end of a boundary.
///
/// # Parameters
///
/// * `byte` - Candidate ASCII byte.
///
/// # Returns
///
/// `true` for an RFC bcharsnospace byte.
#[must_use]
#[inline]
const fn is_boundary_non_space_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?')
}
