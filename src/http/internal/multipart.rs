// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict multipart parsing and bounded diagnostic summary rendering.

use std::io::Write;

use qubit_budget::ResourceBudget;

use super::BoundedBodyWriter;
use super::MultipartPartMetadata;
use super::content_type;
use super::form;
use super::json;
use super::markers;
use crate::RedactionPolicy;
use crate::http::FieldRedactor;
use crate::http::TextBodyPolicy;
use crate::policy::RedactionResource;

/// Redacts one complete multipart body into a deterministic summary.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `boundary` - Validated multipart delimiter boundary.
/// * `require_form_data` - Whether part dispositions must be `form-data`.
/// * `bytes` - Complete bounded body bytes.
/// * `policy` - HTTP policy that supplies body limits and rendering choices.
///
/// # Returns
///
/// A summary, pass-through flag, and rendering-truncation flag, or `None` for
/// malformed input.
#[must_use]
pub(in crate::http) fn redact(
    redactor: &FieldRedactor<'_>,
    boundary: &str,
    require_form_data: bool,
    bytes: &[u8],
    policy: &RedactionPolicy,
) -> Option<(String, bool, bool)> {
    let parts = part_segments(bytes, boundary)?;
    let has_parts = !parts.is_empty();
    let max_output_bytes = policy.body_budget().max_output_bytes();
    let mut output = BoundedBodyWriter::new(max_output_bytes);
    if output.write_all(b"<multipart>\n").is_err() {
        return Some((output.into_string()?, false, true));
    }
    let mut passed = false;
    let mut mask_budget =
        ResourceBudget::new(RedactionResource::Mask, max_output_bytes);
    for (index, part) in parts.into_iter().enumerate() {
        if index > 0 && output.write_all(b"\n").is_err() {
            return Some((output.into_string()?, passed, true));
        }
        let (line, part_passed, part_truncated) = redact_part(
            redactor,
            part,
            policy,
            require_form_data,
            &mut mask_budget,
        )?;
        passed |= part_passed;
        if part_truncated || output.write_all(line.as_bytes()).is_err() {
            return Some((output.into_string()?, passed, true));
        }
    }
    let closing = if has_parts {
        b"\n</multipart>".as_slice()
    } else {
        b"</multipart>".as_slice()
    };
    if output.write_all(closing).is_err() {
        return Some((output.into_string()?, passed, true));
    }
    Some((output.into_string()?, passed, false))
}

/// Redacts one multipart segment.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `segment` - Part bytes without delimiter lines.
/// * `policy` - HTTP policy that supplies body limits and rendering choices.
/// * `require_form_data` - Whether disposition must be `form-data`.
/// * `mask_budget` - Aggregate accounting for generated masks.
///
/// # Returns
///
/// A summary line, pass-through flag, and rendering-truncation flag, or `None`
/// for malformed input.
#[must_use]
fn redact_part(
    redactor: &FieldRedactor<'_>,
    segment: &[u8],
    policy: &RedactionPolicy,
    require_form_data: bool,
    mask_budget: &mut ResourceBudget<RedactionResource, usize>,
) -> Option<(String, bool, bool)> {
    let (headers, body) = split_headers_body(segment)?;
    let mut disposition = None;
    let mut part_type = None;
    for line in headers.lines().filter(|line| !line.trim().is_empty()) {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-disposition") {
            if disposition.replace(value.trim()).is_some() {
                return None;
            }
        } else if name.trim().eq_ignore_ascii_case("content-type")
            && part_type.replace(value.trim()).is_some()
        {
            return None;
        }
    }
    let metadata = MultipartPartMetadata::parse(
        disposition,
        part_type,
        require_form_data,
    )?;
    let name = metadata.name().unwrap_or(markers::MULTIPART_UNNAMED);
    let (value, passed, truncated) = if metadata.filename().is_some() {
        (markers::MULTIPART_FILE.to_string(), false, false)
    } else if name == markers::MULTIPART_UNNAMED {
        (markers::MULTIPART_PART.to_string(), false, false)
    } else {
        let body_text = std::str::from_utf8(body).ok()?;
        if let Some(value) = redactor.redact_bounded_if_sensitive(
            name,
            body_text,
            remaining_mask_bytes(mask_budget),
        ) {
            let value = value.into_owned();
            let consumed = mask_budget.consume_available(value.len());
            debug_assert_eq!(consumed, value.len());
            (value, false, false)
        } else {
            redact_non_sensitive_part(
                redactor,
                body,
                policy,
                metadata.content_type(),
                mask_budget,
            )?
        }
    };
    if truncated {
        return Some((String::new(), passed, true));
    }
    Some((format!("{}={value}", name.escape_debug()), passed, false))
}

/// Redacts a non-sensitive named part according to its declared type.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `body` - Part body bytes.
/// * `policy` - HTTP policy that supplies body limits and rendering choices.
/// * `part_type` - Optional part Content-Type text.
/// * `mask_budget` - Aggregate accounting for generated masks.
///
/// # Returns
///
/// Safe part text, pass-through flag, and rendering-truncation flag, or `None`
/// for invalid UTF-8, JSON, or serialization.
#[must_use]
fn redact_non_sensitive_part(
    redactor: &FieldRedactor<'_>,
    body: &[u8],
    policy: &RedactionPolicy,
    part_type: Option<&str>,
    mask_budget: &mut ResourceBudget<RedactionResource, usize>,
) -> Option<(String, bool, bool)> {
    let text = std::str::from_utf8(body).ok()?;
    match part_type {
        Some(value) if content_type::is_json(value) => {
            let mut value = serde_json::from_slice(body).ok()?;
            let (passed, exhausted) = json::redact_with_mask_budget(
                redactor,
                &mut value,
                policy.json_depth_limit(),
                policy.unkeyed_json_value_policy(),
                mask_budget,
            );
            if exhausted {
                return Some((markers::TRUNCATED.to_string(), false, true));
            }
            json::serialize_bounded(
                &value,
                policy.body_budget().max_output_bytes(),
            )
            .map(|(text, truncated)| (text, passed, truncated))
        }
        Some(value) if content_type::is_ndjson(value) => {
            json::redact_ndjson_with_mask_budget(
                redactor,
                body,
                policy.json_depth_limit(),
                policy.unkeyed_json_value_policy(),
                mask_budget,
                policy.body_budget().max_output_bytes(),
            )
        }
        Some(value) if content_type::is_form(value) => form::is_valid(body)
            .then(|| {
                let value = form::redact_bounded(
                    redactor,
                    body,
                    remaining_mask_bytes(mask_budget),
                );
                let consumed = mask_budget.consume_available(value.len());
                if consumed != value.len() {
                    (String::new(), false, true)
                } else {
                    (value, false, false)
                }
            }),
        Some(value) if content_type::is_text(value) => {
            match policy.text_body_policy() {
                TextBodyPolicy::Redact => {
                    Some((markers::MULTIPART_TEXT.to_string(), false, false))
                }
                TextBodyPolicy::PassThrough => {
                    Some((text.to_string(), true, false))
                }
            }
        }
        None => match policy.text_body_policy() {
            TextBodyPolicy::Redact => {
                Some((markers::MULTIPART_TEXT.to_string(), false, false))
            }
            TextBodyPolicy::PassThrough => {
                Some((text.to_string(), true, false))
            }
        },
        Some(_) => Some((markers::MULTIPART_PART.to_string(), false, false)),
    }
}

/// Returns the mask balance as a platform string length.
fn remaining_mask_bytes(
    budget: &ResourceBudget<RedactionResource, usize>,
) -> usize {
    budget.remaining()
}

/// Splits a complete multipart body into strict delimiter-bounded segments.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the multipart bytes borrowed by returned segments.
///
/// # Parameters
///
/// * `bytes` - Complete multipart bytes.
/// * `boundary` - Validated boundary without delimiter prefix.
///
/// # Returns
///
/// Part segments, or `None` for malformed delimiters or epilogue.
#[must_use]
fn part_segments<'a>(bytes: &'a [u8], boundary: &str) -> Option<Vec<&'a [u8]>> {
    let delimiter = format!("--{boundary}");
    let closing = format!("{delimiter}--");
    let mut start = None;
    let mut result = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        let (line_start, line_end, next) = next_line(bytes, position);
        let line = std::str::from_utf8(&bytes[line_start..line_end]).ok();
        let kind = line.and_then(|line| {
            let line = line.trim_end_matches([' ', '\t']);
            if line == delimiter {
                Some(false)
            } else if line == closing {
                Some(true)
            } else {
                None
            }
        });
        let Some(closing_kind) = kind else {
            position = next;
            continue;
        };
        if let Some(start) = start {
            let part = strip_line_ending(&bytes[start..line_start]);
            if !part.iter().all(u8::is_ascii_whitespace) {
                result.push(part);
            }
        }
        if closing_kind {
            return bytes[next..]
                .iter()
                .all(u8::is_ascii_whitespace)
                .then_some(result);
        }
        start = Some(next);
        position = next;
    }
    None
}

/// Finds the next logical line bounds.
///
/// # Parameters
///
/// * `bytes` - Complete bounded multipart bytes.
/// * `position` - Valid starting offset.
///
/// # Returns
///
/// Start, end without line ending, and next scan position.
///
/// # Panics
///
/// Panics when `position` exceeds `bytes.len()`.
#[must_use]
#[inline]
fn next_line(bytes: &[u8], position: usize) -> (usize, usize, usize) {
    if let Some(relative) =
        bytes[position..].iter().position(|byte| *byte == b'\n')
    {
        let end = position + relative;
        let trimmed = end
            .checked_sub(1)
            .filter(|index| bytes[*index] == b'\r')
            .unwrap_or(end);
        (position, trimmed, end + 1)
    } else {
        (position, bytes.len(), bytes.len())
    }
}

/// Splits a part's UTF-8 headers from its raw body.
///
/// # Parameters
///
/// * `segment` - Complete multipart segment.
///
/// # Returns
///
/// Header text and body bytes, or `None` for missing separation or invalid
/// UTF-8.
#[must_use]
#[inline]
fn split_headers_body(segment: &[u8]) -> Option<(&str, &[u8])> {
    let (header_end, body_start) = segment
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| (index, index + 4))
        .or_else(|| {
            segment
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| (index, index + 2))
        })?;
    Some((
        std::str::from_utf8(&segment[..header_end]).ok()?,
        &segment[body_start..],
    ))
}

/// Removes one multipart line ending.
///
/// # Parameters
///
/// * `value` - Bytes that may end with CRLF or LF.
///
/// # Returns
///
/// The slice without one trailing line ending.
#[must_use]
#[inline(always)]
fn strip_line_ending(value: &[u8]) -> &[u8] {
    value
        .strip_suffix(b"\r\n")
        .or_else(|| value.strip_suffix(b"\n"))
        .unwrap_or(value)
}
