// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Content-Type and header-parameter parsing helpers for HTTP sanitizers.

use http::HeaderValue;

use super::internal::HeaderParameter;

const MAX_MULTIPART_BOUNDARY_LEN: usize = 70;

/// Converts an optional header value to UTF-8 text.
///
/// # Parameters
///
/// * `value` - Optional HTTP header value.
///
/// # Returns
///
/// `Some(Ok(text))` for valid UTF-8 header values, `Some(Err(_))` for present
/// but invalid values, and `None` when no header value is provided.
#[inline(always)]
pub(super) fn content_type_to_str(
    value: Option<&HeaderValue>,
) -> Option<Result<&str, http::header::ToStrError>> {
    value.map(HeaderValue::to_str)
}

/// Returns the media type portion of a Content-Type header.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// Trimmed text before the first semicolon.
#[must_use]
#[inline]
fn media_type(content_type: &str) -> &str {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
}

/// Returns whether a content type has the expected media type.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
/// * `expected` - Expected media type.
///
/// # Returns
///
/// `true` when media types match ignoring ASCII case.
#[must_use]
#[inline]
fn has_media_type(content_type: &str, expected: &str) -> bool {
    media_type(content_type).eq_ignore_ascii_case(expected)
}

/// Returns whether a content type declares JSON.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for `application/json`, subtype aliases ending with `/json`, and
/// structured suffixes ending with `+json`.
#[must_use]
#[inline]
pub(super) fn is_json(content_type: &str) -> bool {
    let media_type = media_type(content_type).to_ascii_lowercase();
    media_type == "application/json"
        || media_type.ends_with("+json")
        || media_type.ends_with("/json")
}

/// Returns whether a content type declares newline-delimited JSON.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for `application/x-ndjson` and `application/ndjson`.
#[must_use]
#[inline]
pub(super) fn is_ndjson(content_type: &str) -> bool {
    let media_type = media_type(content_type);
    media_type.eq_ignore_ascii_case("application/x-ndjson")
        || media_type.eq_ignore_ascii_case("application/ndjson")
}

/// Returns whether a content type declares URL-encoded form data.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for `application/x-www-form-urlencoded`.
#[must_use]
#[inline(always)]
pub(super) fn is_form_urlencoded(content_type: &str) -> bool {
    has_media_type(content_type, "application/x-www-form-urlencoded")
}

/// Returns whether a content type declares multipart data.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for any `multipart/*` media type.
#[must_use]
#[inline]
pub(super) fn is_multipart(content_type: &str) -> bool {
    media_type(content_type)
        .to_ascii_lowercase()
        .starts_with("multipart/")
}

/// Returns whether a content type declares textual data.
///
/// # Parameters
///
/// * `content_type` - Raw Content-Type value.
///
/// # Returns
///
/// `true` for any `text/*` media type.
#[must_use]
#[inline]
pub(super) fn is_text(content_type: &str) -> bool {
    media_type(content_type)
        .to_ascii_lowercase()
        .starts_with("text/")
}

/// Extracts a validated multipart boundary.
///
/// # Parameters
///
/// * `content_type` - Raw multipart Content-Type value.
///
/// # Returns
///
/// Decoded boundary when present and syntactically valid.
pub(super) fn multipart_boundary(content_type: &str) -> Option<String> {
    if !is_multipart(content_type) {
        return None;
    }
    match HeaderParameter::parse(content_type, "boundary") {
        HeaderParameter::Value(boundary)
            if is_valid_multipart_boundary(&boundary) =>
        {
            Some(boundary)
        }
        HeaderParameter::Absent
        | HeaderParameter::Value(_)
        | HeaderParameter::Invalid => None,
    }
}

/// Returns whether a boundary is safe to use as a multipart delimiter.
///
/// # Parameters
///
/// * `boundary` - Boundary parameter value without surrounding quotes.
///
/// # Returns
///
/// `true` when the value uses conservative RFC-compatible ASCII bytes.
#[must_use]
fn is_valid_multipart_boundary(boundary: &str) -> bool {
    let len = boundary.len();
    (1..=MAX_MULTIPART_BOUNDARY_LEN).contains(&len)
        && boundary.bytes().all(is_valid_multipart_boundary_byte)
}

/// Returns whether one byte is valid in a multipart boundary.
///
/// # Parameters
///
/// * `byte` - Boundary byte to test.
///
/// # Returns
///
/// `true` for alphanumeric bytes and conservative punctuation.
#[must_use]
#[inline]
fn is_valid_multipart_boundary_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
            | b'\''
            | b'('
            | b')'
            | b'+'
            | b'_'
            | b','
            | b'-'
            | b'.'
            | b'/'
            | b':'
            | b'='
            | b'?'
    )
}
