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

/// One strict, once-parsed Content-Type classification.
#[must_use]
pub(in crate::http) enum ContentType {
    /// A JSON media type.
    Json,
    /// A newline-delimited JSON media type.
    Ndjson,
    /// A URL-encoded form media type.
    Form,
    /// A multipart media type with its parsed boundary metadata.
    Multipart {
        /// Decoded boundary when it is present and conservatively valid.
        boundary: Option<String>,
        /// Whether each part must declare form-data disposition.
        require_form_data: bool,
    },
    /// An opaque text media type.
    Text,
    /// A syntactically valid but unsupported media type.
    Other,
}

/// Parses and classifies one complete Content-Type exactly once.
///
/// # Parameters
///
/// * `value` - Complete Content-Type text.
///
/// # Returns
///
/// A strict classification, or `None` when media-type or parameter grammar is
/// invalid. Multipart values with a missing or invalid boundary remain valid
/// classifications so callers can report an invalid multipart body.
#[must_use]
pub(in crate::http) fn parse(value: &str) -> Option<ContentType> {
    let media_type = media_type(value);
    let (kind, subtype) = media_type.split_once('/')?;
    if kind.is_empty()
        || subtype.is_empty()
        || !kind.bytes().all(is_token_byte)
        || !subtype.bytes().all(is_token_byte)
    {
        return None;
    }
    let [boundary] = parse_parameters(value, ["boundary"])?;
    if is_multipart_media_type(media_type) {
        return Some(ContentType::Multipart {
            boundary: validate_boundary(boundary),
            require_form_data: media_type
                .eq_ignore_ascii_case("multipart/form-data"),
        });
    }
    if is_ndjson_media_type(media_type) {
        return Some(ContentType::Ndjson);
    }
    if is_json_media_type(media_type) {
        return Some(ContentType::Json);
    }
    if media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return Some(ContentType::Form);
    }
    if is_text_media_type(media_type) {
        return Some(ContentType::Text);
    }
    Some(ContentType::Other)
}

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
    is_json_media_type(media_type(value))
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
    is_ndjson_media_type(media_type(value))
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
    is_text_media_type(media_type(value))
}

/// Reports whether a media type has a case-insensitive ASCII prefix.
///
/// # Parameters
///
/// * `value` - Media type text to inspect.
/// * `prefix` - ASCII prefix to compare.
///
/// # Returns
///
/// `true` when the value starts with the complete prefix.
#[must_use]
#[inline]
fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

/// Reports whether a media type has a case-insensitive ASCII suffix.
///
/// # Parameters
///
/// * `value` - Media type text to inspect.
/// * `suffix` - ASCII suffix to compare.
///
/// # Returns
///
/// `true` when the value ends with the complete suffix.
#[must_use]
#[inline]
fn ends_with_ascii_case_insensitive(value: &str, suffix: &str) -> bool {
    value
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|end| end.eq_ignore_ascii_case(suffix))
}

/// Reports whether a media type declares JSON.
///
/// # Parameters
///
/// * `value` - Media type portion without parameters.
///
/// # Returns
///
/// `true` for JSON media types and structured JSON suffixes.
#[must_use]
#[inline]
fn is_json_media_type(value: &str) -> bool {
    value.eq_ignore_ascii_case("application/json")
        || ends_with_ascii_case_insensitive(value, "+json")
        || ends_with_ascii_case_insensitive(value, "/json")
}

/// Reports whether a media type declares NDJSON.
///
/// # Parameters
///
/// * `value` - Media type portion without parameters.
///
/// # Returns
///
/// `true` for either supported NDJSON media type.
#[must_use]
#[inline]
fn is_ndjson_media_type(value: &str) -> bool {
    value.eq_ignore_ascii_case("application/x-ndjson")
        || value.eq_ignore_ascii_case("application/ndjson")
}

/// Reports whether a media type declares multipart content.
///
/// # Parameters
///
/// * `value` - Media type portion without parameters.
///
/// # Returns
///
/// `true` for any multipart subtype.
#[must_use]
#[inline]
fn is_multipart_media_type(value: &str) -> bool {
    starts_with_ascii_case_insensitive(value, "multipart/")
}

/// Reports whether a media type declares opaque text.
///
/// # Parameters
///
/// * `value` - Media type portion without parameters.
///
/// # Returns
///
/// `true` for any text subtype.
#[must_use]
#[inline]
fn is_text_media_type(value: &str) -> bool {
    starts_with_ascii_case_insensitive(value, "text/")
}

/// Validates an optional decoded multipart boundary.
///
/// # Parameters
///
/// * `boundary` - Decoded boundary parameter, if one was present.
///
/// # Returns
///
/// The boundary when it satisfies conservative multipart framing rules.
#[must_use]
fn validate_boundary(boundary: Option<String>) -> Option<String> {
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
