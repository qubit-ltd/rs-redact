/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Content-Type and header-parameter parsing helpers for HTTP sanitizers.

use http::HeaderValue;

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
pub(super) fn content_type_to_str(value: Option<&HeaderValue>) -> Option<Result<&str, http::header::ToStrError>> {
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
fn media_type(content_type: &str) -> &str {
    content_type.split(';').next().map(str::trim).unwrap_or_default()
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
pub(super) fn is_json(content_type: &str) -> bool {
    let media_type = media_type(content_type).to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json") || media_type.ends_with("/json")
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
pub(super) fn is_ndjson(content_type: &str) -> bool {
    let media_type = media_type(content_type);
    media_type.eq_ignore_ascii_case("application/x-ndjson") || media_type.eq_ignore_ascii_case("application/ndjson")
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
pub(super) fn is_multipart(content_type: &str) -> bool {
    media_type(content_type).to_ascii_lowercase().starts_with("multipart/")
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
pub(super) fn is_text(content_type: &str) -> bool {
    media_type(content_type).to_ascii_lowercase().starts_with("text/")
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
    let boundary = parameter(content_type, "boundary")?;
    if is_valid_multipart_boundary(&boundary) {
        Some(boundary)
    } else {
        None
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
fn is_valid_multipart_boundary(boundary: &str) -> bool {
    let len = boundary.len();
    (1..=MAX_MULTIPART_BOUNDARY_LEN).contains(&len) && boundary.bytes().all(is_valid_multipart_boundary_byte)
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

/// Extracts a semicolon-separated header parameter.
///
/// # Parameters
///
/// * `value` - Header value containing parameters.
/// * `parameter_name` - Parameter name to extract.
///
/// # Returns
///
/// Decoded parameter value, or `None` when absent or malformed.
pub(super) fn parameter(value: &str, parameter_name: &str) -> Option<String> {
    for segment in header_parameter_segments(value)?.into_iter().skip(1) {
        let Some((name, raw_value)) = segment.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case(parameter_name) {
            continue;
        }
        return decode_header_parameter(raw_value.trim());
    }
    None
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
