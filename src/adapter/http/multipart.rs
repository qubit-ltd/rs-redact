// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
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
        HeaderParameter,
        MultipartDelimiter,
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
) -> Option<String> {
    let boundary = content_type::multipart_boundary(content_type?)?;
    let text = std::str::from_utf8(bytes).ok()?;
    let segments = multipart_part_segments(text, &boundary)?;
    let mut lines = Vec::with_capacity(segments.len());
    for segment in segments {
        lines.push(sanitize_multipart_part(sanitizer, segment, match_mode)?);
    }
    if lines.is_empty() {
        return Some("<multipart>\n</multipart>".to_string());
    }
    Some(format!("<multipart>\n{}\n</multipart>", lines.join("\n")))
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
) -> Option<String> {
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
    let disposition = content_disposition.unwrap_or_default();
    let name = match HeaderParameter::parse(disposition, "name") {
        HeaderParameter::Absent => None,
        HeaderParameter::Value(name) => Some(name),
        HeaderParameter::Invalid => return None,
    };
    let filename = match HeaderParameter::parse(disposition, "filename") {
        HeaderParameter::Absent => None,
        HeaderParameter::Value(filename) => Some(filename),
        HeaderParameter::Invalid => return None,
    };
    let extended_filename =
        match HeaderParameter::parse(disposition, "filename*") {
            HeaderParameter::Absent => None,
            HeaderParameter::Value(filename) => Some(filename),
            HeaderParameter::Invalid => return None,
        };
    let filename = filename.or(extended_filename);
    let field_name = name.as_deref().unwrap_or(MULTIPART_UNNAMED_FIELD);
    let value = sanitize_multipart_part_value(
        sanitizer,
        field_name,
        filename.as_deref(),
        content_type,
        body,
        match_mode,
    );
    Some(format!("{field_name}={value}"))
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
) -> String {
    if sanitizer
        .field_sanitizer()
        .sensitivity_for_name(field_name, match_mode)
        .is_some()
    {
        return sanitizer
            .field_sanitizer()
            .sanitize_value(field_name, body, match_mode)
            .into_owned();
    }
    if filename.is_some() {
        return MULTIPART_FILE_PART_REDACTED.to_string();
    }
    if field_name == MULTIPART_UNNAMED_FIELD {
        return MULTIPART_PART_REDACTED.to_string();
    }
    let Some(content_type) = content_type else {
        return sanitize_text_part(sanitizer, body);
    };
    if content_type::is_json(content_type) {
        return sanitizer
            .sanitize_json(body.as_bytes(), match_mode)
            .unwrap_or_else(|| MULTIPART_PART_REDACTED.to_string());
    }
    if content_type::is_ndjson(content_type) {
        return sanitizer
            .sanitize_ndjson(body.as_bytes(), match_mode)
            .unwrap_or_else(|| MULTIPART_PART_REDACTED.to_string());
    }
    if content_type::is_form_urlencoded(content_type) {
        return sanitizer.sanitize_form(body.as_bytes(), match_mode);
    }
    if content_type::is_text(content_type) {
        return sanitize_text_part(sanitizer, body);
    }
    MULTIPART_PART_REDACTED.to_string()
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
fn sanitize_text_part(sanitizer: &HttpBodySanitizer, body: &str) -> String {
    match sanitizer.text_body_policy() {
        TextBodyPolicy::Redact => MULTIPART_TEXT_PART_REDACTED.to_string(),
        TextBodyPolicy::PassThrough => body.to_string(),
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
    let mut current_start = None;
    let mut segments = Vec::new();
    let mut position = 0;
    while position < text.len() {
        let (line_start, line_end, next_position) =
            next_line_bounds(text, position);
        let line = &text[line_start..line_end];
        let Some(delimiter) = MultipartDelimiter::classify(line, boundary)
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
        if delimiter == MultipartDelimiter::Closing {
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
fn strip_one_trailing_line_ending(value: &str) -> &str {
    value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value)
}
