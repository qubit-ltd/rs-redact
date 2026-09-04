// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict multipart parsing and bounded diagnostic summary rendering.

use std::io::Write;

use super::super::admitted_body::AdmittedMultipart;
use super::super::admitted_body::AdmittedMultipartBody;
use super::BoundedBodyWriter;
use super::MultipartPartMetadata;
use super::content_type;
use super::form;
use super::json;
use super::markers;
use crate::RedactionPolicy;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::formats::http::FieldRedactor;
use crate::formats::http::TextBodyPolicy;
use crate::runtime::InspectionSession;
use crate::runtime::runtime_session::RuntimeSession;

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
pub(in crate::formats::http) fn redact(
    redactor: &FieldRedactor<'_>,
    boundary: &str,
    require_form_data: bool,
    bytes: &[u8],
    policy: &RedactionPolicy,
    max_output_bytes: usize,
    admitted: Option<&mut AdmittedMultipart>,
) -> Option<(String, bool, bool)> {
    let parts = part_segments(bytes, boundary)?;
    if admitted
        .as_ref()
        .is_some_and(|admitted| admitted.parts.len() != parts.len())
    {
        return None;
    }
    let has_parts = !parts.is_empty();
    let mut output = BoundedBodyWriter::new(max_output_bytes);
    if output.write_all(b"<multipart>\n").is_err() {
        return Some((output.into_string()?, false, true));
    }
    let mut passed = false;
    for (index, part) in parts.into_iter().enumerate() {
        if index > 0 && output.write_all(b"\n").is_err() {
            return Some((output.into_string()?, passed, true));
        }
        let parsed = admitted.as_ref().map(|admitted| admitted.parts[index].as_ref());
        let (line, part_passed, part_truncated) =
            redact_part(redactor, part, policy, require_form_data, max_output_bytes, parsed)?;
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

/// Charges multipart parts and nested structured values to one transaction.
#[must_use]
pub(in crate::formats::http) fn admit_structure(
    session: &mut dyn RuntimeSession,
    boundary: &str,
    require_form_data: bool,
    bytes: &[u8],
) -> Option<AdmittedMultipart> {
    let Some(parts) = part_segments(bytes, boundary) else {
        return Some(AdmittedMultipart { parts: Vec::new() });
    };
    let mut admitted = Vec::with_capacity(parts.len());
    for part in parts {
        if !session.admit_format_collection_item() || !session.admit_format_node(2) {
            return None;
        }
        let Some((metadata, body)) = parse_part(part, require_form_data) else {
            return Some(AdmittedMultipart { parts: Vec::new() });
        };
        let Some(name) = metadata.name() else {
            admitted.push(None);
            continue;
        };
        if metadata.filename().is_some() || body_field_is_sensitive(session, name) {
            admitted.push(None);
            continue;
        }
        let value = match metadata.content_type() {
            Some(value) if content_type::is_json(value) => {
                let Ok(text) = std::str::from_utf8(body) else {
                    admitted.push(None);
                    continue;
                };
                let value = crate::formats::json::admit_json_text_value_at_depth(session, text, 3).ok()?;
                Some(AdmittedMultipartBody::Json(value))
            }
            Some(value) if content_type::is_ndjson(value) => {
                let Ok(text) = std::str::from_utf8(body) else {
                    admitted.push(None);
                    continue;
                };
                let mut lines = Vec::new();
                for line in text.lines().filter(|line| !line.trim().is_empty()) {
                    lines.push(Some(
                        crate::formats::json::admit_json_text_value_at_depth(session, line, 3).ok()?,
                    ));
                }
                Some(AdmittedMultipartBody::Ndjson {
                    lines,
                    trailing_newline: text.ends_with('\n'),
                })
            }
            Some(value) if content_type::is_form(value) => {
                if !admit_form_fields(session, body, 3) {
                    return None;
                }
                None
            }
            Some(_) | None => None,
        };
        admitted.push(value);
    }
    Some(AdmittedMultipart { parts: admitted })
}

/// Classifies every multipart part without rendering or retaining body data.
pub(in crate::formats::http) fn inspect(
    session: &mut InspectionSession,
    boundary: &str,
    require_form_data: bool,
    bytes: &[u8],
) {
    let Some(parts) = part_segments(bytes, boundary) else {
        session.fail_inspection(RedactionReason::InvalidMultipart);
        return;
    };
    for part in parts {
        if !session.preflight_format_item(2) || !session.admit_format_collection_item() || !session.admit_format_node(2)
        {
            return;
        }
        let Some((metadata, body)) = parse_part(part, require_form_data) else {
            session.fail_inspection(RedactionReason::InvalidMultipart);
            return;
        };
        let Some(name) = metadata.name() else {
            session.observe_sensitivity(Sensitivity::Secret);
            continue;
        };
        if metadata.filename().is_some() {
            session.observe_sensitivity(Sensitivity::Secret);
            continue;
        }
        let field_redactor = FieldRedactor::new(
            session.policy().rules(),
            session.policy().http().body_rules(),
            session.policy().masking(),
        );
        if let Some(sensitivity) = field_redactor.sensitivity(name) {
            session.observe_sensitivity(sensitivity);
            continue;
        }
        match metadata.content_type() {
            Some(value) if content_type::is_json(value) => {
                crate::formats::http::inspection::inspect_json_bytes(session, body);
            }
            Some(value) if content_type::is_ndjson(value) => {
                crate::formats::http::inspection::inspect_ndjson(session, body);
            }
            Some(value) if content_type::is_form(value) => {
                crate::formats::http::inspection::inspect_form(session, body);
            }
            Some(value) if content_type::is_text(value) => {
                if std::str::from_utf8(body).is_err() {
                    session.fail_inspection(RedactionReason::InvalidMultipart);
                    return;
                }
                if session.policy().http().text_body_policy() == TextBodyPolicy::Redact {
                    session.observe_sensitivity(Sensitivity::Secret);
                }
            }
            None => {
                if std::str::from_utf8(body).is_err() {
                    session.fail_inspection(RedactionReason::InvalidMultipart);
                    return;
                }
                if session.policy().http().text_body_policy() == TextBodyPolicy::Redact {
                    session.observe_sensitivity(Sensitivity::Secret);
                }
            }
            Some(_) => session.observe_sensitivity(Sensitivity::Secret),
        }
    }
}

/// Charges each non-empty URL-encoded form field at `field_depth`.
#[must_use]
pub(in crate::formats::http) fn admit_form_fields(
    session: &mut dyn RuntimeSession,
    bytes: &[u8],
    field_depth: usize,
) -> bool {
    if bytes.is_empty() {
        return true;
    }
    bytes
        .split(|byte| *byte == b'&')
        .all(|_| session.admit_format_collection_item() && session.admit_format_node(field_depth))
}

/// Resolves body rules without retaining an immutable session borrow.
#[must_use]
fn body_field_is_sensitive(session: &dyn RuntimeSession, field: &str) -> bool {
    let policy = session.policy();
    FieldRedactor::new(policy.rules(), policy.http().body_rules(), policy.masking()).is_sensitive(field)
}

/// Redacts one multipart segment.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `segment` - Part bytes without delimiter lines.
/// * `policy` - HTTP policy that supplies body limits and rendering choices.
/// * `require_form_data` - Whether disposition must be `form-data`.
/// * `max_output_bytes` - Remaining transaction output allowance supplied by
///   the caller.
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
    max_output_bytes: usize,
    admitted: Option<Option<&AdmittedMultipartBody>>,
) -> Option<(String, bool, bool)> {
    let (metadata, body) = parse_part(segment, require_form_data)?;
    let name = metadata.name().unwrap_or(markers::MULTIPART_UNNAMED);
    let (value, passed, truncated) = if metadata.filename().is_some() {
        (markers::MULTIPART_FILE.to_string(), false, false)
    } else if name == markers::MULTIPART_UNNAMED {
        (markers::MULTIPART_PART.to_string(), false, false)
    } else {
        let body_text = std::str::from_utf8(body).ok()?;
        if let Some(value) = redactor.redact_bounded_if_sensitive(name, body_text, max_output_bytes) {
            let value = value.into_owned();
            (value, false, false)
        } else {
            redact_non_sensitive_part(
                redactor,
                body,
                policy,
                metadata.content_type(),
                max_output_bytes,
                admitted,
            )?
        }
    };
    if truncated {
        return Some((String::new(), passed, true));
    }
    Some((format!("{}={value}", name.escape_debug()), passed, false))
}

/// Parses one part's headers and metadata without inspecting its body.
#[must_use]
fn parse_part(segment: &[u8], require_form_data: bool) -> Option<(MultipartPartMetadata<'_>, &[u8])> {
    let (headers, body) = split_headers_body(segment)?;
    let mut disposition = None;
    let mut part_type = None;
    for line in headers.lines().filter(|line| !line.trim().is_empty()) {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-disposition") {
            if disposition.replace(value.trim()).is_some() {
                return None;
            }
        } else if name.trim().eq_ignore_ascii_case("content-type") && part_type.replace(value.trim()).is_some() {
            return None;
        }
    }
    let metadata = MultipartPartMetadata::parse(disposition, part_type, require_form_data)?;
    Some((metadata, body))
}

/// Redacts a non-sensitive named part according to its declared type.
///
/// # Parameters
///
/// * `redactor` - Structured-body field redactor.
/// * `body` - Part body bytes.
/// * `policy` - HTTP policy that supplies body limits and rendering choices.
/// * `part_type` - Optional part Content-Type text.
/// * `max_output_bytes` - Remaining transaction output allowance supplied by
///   the caller.
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
    max_output_bytes: usize,
    admitted: Option<Option<&AdmittedMultipartBody>>,
) -> Option<(String, bool, bool)> {
    let text = std::str::from_utf8(body).ok()?;
    match part_type {
        Some(value) if content_type::is_json(value) => {
            let mut value = match admitted? {
                Some(AdmittedMultipartBody::Json(value)) => value.clone(),
                _ => return None,
            };
            let passed = json::redact(redactor, &mut value, policy.unkeyed_json_value_policy());
            json::serialize_bounded(&value, max_output_bytes).map(|(text, truncated)| (text, passed, truncated))
        }
        Some(value) if content_type::is_ndjson(value) => {
            let AdmittedMultipartBody::Ndjson {
                lines,
                trailing_newline,
            } = admitted??
            else {
                return None;
            };
            let mut lines = lines.clone();
            json::redact_ndjson_values(
                redactor,
                &mut lines,
                *trailing_newline,
                policy.unkeyed_json_value_policy(),
                max_output_bytes,
            )
        }
        Some(value) if content_type::is_form(value) => form::is_valid(body).then(|| {
            let value = form::redact_bounded(redactor, body, max_output_bytes);
            (value, false, false)
        }),
        Some(value) if content_type::is_text(value) => match policy.http().text_body_policy() {
            TextBodyPolicy::Redact => Some((markers::MULTIPART_TEXT.to_string(), false, false)),
            TextBodyPolicy::PassThrough => Some((text.to_string(), true, false)),
        },
        None => match policy.http().text_body_policy() {
            TextBodyPolicy::Redact => Some((markers::MULTIPART_TEXT.to_string(), false, false)),
            TextBodyPolicy::PassThrough => Some((text.to_string(), true, false)),
        },
        Some(_) => Some((markers::MULTIPART_PART.to_string(), false, false)),
    }
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
            return bytes[next..].iter().all(u8::is_ascii_whitespace).then_some(result);
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
    if let Some(relative) = bytes[position..].iter().position(|byte| *byte == b'\n') {
        let end = position + relative;
        let trimmed = end.checked_sub(1).filter(|index| bytes[*index] == b'\r').unwrap_or(end);
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
