// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Multipart body parsing and sanitized diagnostic summary rendering.

use crate::{
    NameMatchMode,
    escape_log_control_characters,
};

use super::{
    content_type,
    http_body_sanitizer::HttpBodySanitizer,
    internal::{
        MultipartDelimiter,
        MultipartPartMetadata,
        MultipartSanitization,
    },
    redaction_markers::{
        MULTIPART_FILE_PART_REDACTED,
        MULTIPART_PART_REDACTED,
        MULTIPART_TEXT_PART_REDACTED,
        MULTIPART_UNNAMED_FIELD,
    },
    text_body_policy::TextBodyPolicy,
};

/// Sanitizes a complete multipart body into a log summary.
///
/// # Parameters
///
/// * `sanitizer` - HTTP body sanitizer used for nested part values.
/// * `content_type` - Multipart content type text.
/// * `bytes` - Complete multipart body bytes.
/// * `match_mode` - Field-name matching mode for multipart field names.
///
/// # Returns
///
/// Sanitized multipart summary, or `None` when the body must be redacted.
pub(super) fn sanitize_multipart(
    sanitizer: &HttpBodySanitizer,
    content_type: Option<&str>,
    bytes: &[u8],
    match_mode: NameMatchMode,
) -> Option<MultipartSanitization> {
    let boundary = content_type::multipart_boundary(content_type?)?;
    let segments = multipart_part_segments(bytes, &boundary)?;
    let mut lines = Vec::with_capacity(segments.len());
    let mut contains_passed_through_value = false;
    for segment in segments {
        let part = sanitize_multipart_part(sanitizer, segment, match_mode)?;
        contains_passed_through_value |= part.contains_passed_through_value();
        lines.push(part.into_content());
    }
    if lines.is_empty() {
        return Some(MultipartSanitization::new(
            "<multipart>\n</multipart>".to_string(),
            false,
        ));
    }
    Some(MultipartSanitization::new(
        format!("<multipart>\n{}\n</multipart>", lines.join("\n")),
        contains_passed_through_value,
    ))
}

/// Sanitizes one multipart part into a summary line.
///
/// # Parameters
///
/// * `sanitizer` - HTTP body sanitizer used for nested part values.
/// * `segment` - Raw part segment without boundary delimiter lines.
/// * `match_mode` - Field-name matching mode for multipart field names.
///
/// # Returns
///
/// Sanitized `name=value` line, or `None` when part headers are malformed.
fn sanitize_multipart_part(
    sanitizer: &HttpBodySanitizer,
    segment: &[u8],
    match_mode: NameMatchMode,
) -> Option<MultipartSanitization> {
    let (headers, body) = split_multipart_headers_and_body(segment)?;
    let mut content_disposition = None;
    let mut content_type = None;
    for line in headers.lines().filter(|line| !line.trim().is_empty()) {
        let (header_name, header_value) = line.split_once(':')?;
        let header_name = header_name.trim();
        let header_value = header_value.trim();
        if header_name.eq_ignore_ascii_case("content-disposition") {
            if content_disposition.replace(header_value).is_some() {
                return None;
            }
        } else if header_name.eq_ignore_ascii_case("content-type")
            && content_type.replace(header_value).is_some()
        {
            return None;
        }
    }
    let metadata = MultipartPartMetadata::parse(
        content_disposition.unwrap_or_default(),
        content_type,
    )?;
    let field_name = metadata.name().unwrap_or(MULTIPART_UNNAMED_FIELD);
    let value = sanitize_multipart_part_value(
        sanitizer,
        field_name,
        metadata.filename(),
        metadata.content_type(),
        body,
        match_mode,
    )?;
    let displayed_field_name = field_name.escape_debug().collect::<String>();
    let contains_passed_through_value = value.contains_passed_through_value();
    Some(MultipartSanitization::new(
        format!("{displayed_field_name}={}", value.content()),
        contains_passed_through_value,
    ))
}

/// Sanitizes one multipart part value.
///
/// # Parameters
///
/// * `sanitizer` - HTTP body sanitizer used for nested part values.
/// * `field_name` - Parsed multipart field name.
/// * `filename` - Optional filename from `Content-Disposition`.
/// * `content_type` - Optional part-level content type.
/// * `body` - Part body text.
/// * `match_mode` - Field-name matching mode for multipart field names.
///
/// # Returns
///
/// Sanitized part value for diagnostic output, or `None` when a non-file body
/// is not valid UTF-8.
fn sanitize_multipart_part_value(
    sanitizer: &HttpBodySanitizer,
    field_name: &str,
    filename: Option<&str>,
    content_type: Option<&str>,
    body: &[u8],
    match_mode: NameMatchMode,
) -> Option<MultipartSanitization> {
    if filename.is_some() {
        return Some(sanitized_part(MULTIPART_FILE_PART_REDACTED.to_string()));
    }
    let body = std::str::from_utf8(body).ok()?;
    if let Some(level) = sanitizer
        .field_sanitizer()
        .sensitivity_for_name(field_name, match_mode)
    {
        let masked =
            sanitizer.field_sanitizer().mask_value_at_level(body, level);
        return Some(sanitized_part(
            escape_log_control_characters(masked.as_ref()).into_owned(),
        ));
    }
    if field_name == MULTIPART_UNNAMED_FIELD {
        return Some(sanitized_part(MULTIPART_PART_REDACTED.to_string()));
    }
    let Some(content_type) = content_type else {
        return Some(sanitize_text_part(sanitizer, body));
    };
    if content_type::is_json(content_type) {
        let (content, contains_passed_through_value) = sanitizer
            .sanitize_json(body.as_bytes(), match_mode)
            .unwrap_or_else(|| (MULTIPART_PART_REDACTED.to_string(), false));
        return Some(MultipartSanitization::new(
            content,
            contains_passed_through_value,
        ));
    }
    if content_type::is_ndjson(content_type) {
        let (content, contains_passed_through_value) = sanitizer
            .sanitize_ndjson(body.as_bytes(), match_mode)
            .unwrap_or_else(|| (MULTIPART_PART_REDACTED.to_string(), false));
        return Some(MultipartSanitization::new(
            content,
            contains_passed_through_value,
        ));
    }
    if content_type::is_form_urlencoded(content_type) {
        return Some(sanitized_part(
            sanitizer.sanitize_form(body.as_bytes(), match_mode),
        ));
    }
    if content_type::is_text(content_type) {
        return Some(sanitize_text_part(sanitizer, body));
    }
    Some(sanitized_part(MULTIPART_PART_REDACTED.to_string()))
}

/// Wraps content that contains no passed-through opaque text.
///
/// # Parameters
///
/// * `content` - Sanitized or redacted multipart part content.
///
/// # Returns
///
/// Multipart result with opaque-text exposure set to `false`.
#[inline(always)]
fn sanitized_part(content: String) -> MultipartSanitization {
    MultipartSanitization::new(content, false)
}

/// Sanitizes a multipart text part according to the body text policy.
///
/// # Parameters
///
/// * `sanitizer` - HTTP body sanitizer that owns the text policy.
/// * `body` - UTF-8 text part without structured field names.
///
/// # Returns
///
/// A text-part redaction marker by default, or `body` unchanged when callers
/// explicitly choose [`TextBodyPolicy::PassThrough`].
#[inline]
fn sanitize_text_part(
    sanitizer: &HttpBodySanitizer,
    body: &str,
) -> MultipartSanitization {
    match sanitizer.text_body_policy() {
        TextBodyPolicy::Redact => {
            sanitized_part(MULTIPART_TEXT_PART_REDACTED.to_string())
        }
        TextBodyPolicy::PassThrough => {
            MultipartSanitization::new(body.to_string(), true)
        }
    }
}

/// Splits a complete multipart body into part segments.
///
/// # Parameters
///
/// * `bytes` - Multipart body bytes.
/// * `boundary` - Boundary parameter without the leading `--`.
///
/// # Returns
///
/// Raw part segments without boundary delimiter lines, or `None` for malformed
/// multipart bodies.
fn multipart_part_segments<'a>(
    bytes: &'a [u8],
    boundary: &str,
) -> Option<Vec<&'a [u8]>> {
    let delimiter = format!("--{boundary}");
    let closing_delimiter = format!("{delimiter}--");
    let mut current_start = None;
    let mut segments = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        let (line_start, line_end, next_position) =
            next_line_bounds(bytes, position);
        let delimiter_kind = std::str::from_utf8(&bytes[line_start..line_end])
            .ok()
            .and_then(|line| {
                MultipartDelimiter::classify(
                    line,
                    &delimiter,
                    &closing_delimiter,
                )
            });
        let Some(delimiter_kind) = delimiter_kind else {
            position = next_position;
            continue;
        };
        if let Some(start) = current_start {
            let segment =
                strip_one_trailing_line_ending(&bytes[start..line_start]);
            if !segment.iter().all(|byte| byte.is_ascii_whitespace()) {
                segments.push(segment);
            }
        }
        if delimiter_kind == MultipartDelimiter::Closing {
            if bytes[next_position..]
                .iter()
                .all(|byte| byte.is_ascii_whitespace())
            {
                return Some(segments);
            }
            return None;
        }
        current_start = Some(next_position);
        position = next_position;
    }
    None
}

/// Returns the next line range and following scan position.
///
/// # Parameters
///
/// * `bytes` - Source bytes.
/// * `position` - Byte offset where the next line starts.
///
/// # Returns
///
/// `(line_start, line_end_without_line_ending, next_position)`.
///
/// # Panics
///
/// Panics when `position` exceeds `bytes.len()`.
#[must_use]
#[inline]
fn next_line_bounds(bytes: &[u8], position: usize) -> (usize, usize, usize) {
    if let Some(relative_end) =
        bytes[position..].iter().position(|byte| *byte == b'\n')
    {
        let line_end = position + relative_end;
        let trimmed_end = line_end
            .checked_sub(1)
            .filter(|index| bytes[*index] == b'\r')
            .unwrap_or(line_end);
        return (position, trimmed_end, line_end + 1);
    }
    (position, bytes.len(), bytes.len())
}

/// Splits multipart part headers from the part body.
///
/// # Parameters
///
/// * `segment` - Raw part segment.
///
/// # Returns
///
/// UTF-8 header text and raw body bytes.
#[inline]
fn split_multipart_headers_and_body(segment: &[u8]) -> Option<(&str, &[u8])> {
    let (header_end, body_start) = if let Some(index) =
        segment.windows(4).position(|window| window == b"\r\n\r\n")
    {
        (index, index + 4)
    } else {
        let index = segment.windows(2).position(|window| window == b"\n\n")?;
        (index, index + 2)
    };
    let headers = std::str::from_utf8(&segment[..header_end]).ok()?;
    Some((headers, &segment[body_start..]))
}

/// Removes one trailing multipart line ending.
///
/// # Parameters
///
/// * `value` - Bytes that may end with one line ending.
///
/// # Returns
///
/// Bytes without one trailing line ending.
#[must_use]
#[inline]
fn strip_one_trailing_line_ending(value: &[u8]) -> &[u8] {
    value
        .strip_suffix(b"\r\n")
        .or_else(|| value.strip_suffix(b"\n"))
        .unwrap_or(value)
}
