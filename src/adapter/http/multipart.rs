// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Multipart body parsing and sanitized diagnostic summary rendering.

use crate::NameMatchMode;

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
    let text = std::str::from_utf8(bytes).ok()?;
    let segments = multipart_part_segments(text, &boundary)?;
    let mut lines = Vec::with_capacity(segments.len());
    let mut contains_passed_through_text = false;
    for segment in segments {
        let part = sanitize_multipart_part(sanitizer, segment, match_mode)?;
        contains_passed_through_text |= part.contains_passed_through_text();
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
        contains_passed_through_text,
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
    segment: &str,
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
    );
    let displayed_field_name = field_name.escape_debug().collect::<String>();
    let contains_passed_through_text = value.contains_passed_through_text();
    Some(MultipartSanitization::new(
        format!("{displayed_field_name}={}", value.content()),
        contains_passed_through_text,
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
/// Sanitized part value for diagnostic output.
fn sanitize_multipart_part_value(
    sanitizer: &HttpBodySanitizer,
    field_name: &str,
    filename: Option<&str>,
    content_type: Option<&str>,
    body: &str,
    match_mode: NameMatchMode,
) -> MultipartSanitization {
    if filename.is_some() {
        return sanitized_part(MULTIPART_FILE_PART_REDACTED.to_string());
    }
    if let Some(level) = sanitizer
        .field_sanitizer()
        .sensitivity_for_name(field_name, match_mode)
    {
        return sanitized_part(
            sanitizer
                .field_sanitizer()
                .mask_value_at_level(body, level)
                .into_owned(),
        );
    }
    if field_name == MULTIPART_UNNAMED_FIELD {
        return sanitized_part(MULTIPART_PART_REDACTED.to_string());
    }
    let Some(content_type) = content_type else {
        return sanitize_text_part(sanitizer, body);
    };
    if content_type::is_json(content_type) {
        return sanitized_part(
            sanitizer
                .sanitize_json(body.as_bytes(), match_mode)
                .unwrap_or_else(|| MULTIPART_PART_REDACTED.to_string()),
        );
    }
    if content_type::is_ndjson(content_type) {
        return sanitized_part(
            sanitizer
                .sanitize_ndjson(body.as_bytes(), match_mode)
                .unwrap_or_else(|| MULTIPART_PART_REDACTED.to_string()),
        );
    }
    if content_type::is_form_urlencoded(content_type) {
        return sanitized_part(
            sanitizer.sanitize_form(body.as_bytes(), match_mode),
        );
    }
    if content_type::is_text(content_type) {
        return sanitize_text_part(sanitizer, body);
    }
    sanitized_part(MULTIPART_PART_REDACTED.to_string())
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
/// * `text` - Multipart body text.
/// * `boundary` - Boundary parameter without the leading `--`.
///
/// # Returns
///
/// Raw part segments without boundary delimiter lines, or `None` for malformed
/// multipart bodies.
fn multipart_part_segments<'a>(
    text: &'a str,
    boundary: &str,
) -> Option<Vec<&'a str>> {
    let delimiter = format!("--{boundary}");
    let closing_delimiter = format!("{delimiter}--");
    let mut current_start = None;
    let mut segments = Vec::new();
    let mut position = 0;
    while position < text.len() {
        let (line_start, line_end, next_position) =
            next_line_bounds(text, position);
        let line = &text[line_start..line_end];
        let Some(delimiter_kind) =
            MultipartDelimiter::classify(line, &delimiter, &closing_delimiter)
        else {
            position = next_position;
            continue;
        };
        if let Some(start) = current_start {
            let segment =
                strip_one_trailing_line_ending(&text[start..line_start]);
            if !segment.trim().is_empty() {
                segments.push(segment);
            }
        }
        if delimiter_kind == MultipartDelimiter::Closing {
            if text[next_position..].trim().is_empty() {
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
/// * `text` - Source text.
/// * `position` - Byte offset where the next line starts.
///
/// # Returns
///
/// `(line_start, line_end_without_line_ending, next_position)`.
///
/// # Panics
///
/// Panics when `position` exceeds `text.len()` or is not a UTF-8 character
/// boundary.
#[must_use]
#[inline]
fn next_line_bounds(text: &str, position: usize) -> (usize, usize, usize) {
    if let Some(relative_end) = text[position..].find('\n') {
        let line_end = position + relative_end;
        let trimmed_end = line_end
            .checked_sub(1)
            .filter(|index| text.as_bytes()[*index] == b'\r')
            .unwrap_or(line_end);
        return (position, trimmed_end, line_end + 1);
    }
    (position, text.len(), text.len())
}

/// Splits multipart part headers from the part body.
///
/// # Parameters
///
/// * `segment` - Raw part segment.
///
/// # Returns
///
/// Header text and body text.
#[inline]
fn split_multipart_headers_and_body(segment: &str) -> Option<(&str, &str)> {
    if let Some(index) = segment.find("\r\n\r\n") {
        return Some((&segment[..index], &segment[index + 4..]));
    }
    if let Some(index) = segment.find("\n\n") {
        return Some((&segment[..index], &segment[index + 2..]));
    }
    None
}

/// Removes one trailing multipart line ending.
///
/// # Parameters
///
/// * `value` - Text that may end with one line ending.
///
/// # Returns
///
/// Text without one trailing line ending.
#[must_use]
#[inline(always)]
fn strip_one_trailing_line_ending(value: &str) -> &str {
    value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value)
}
