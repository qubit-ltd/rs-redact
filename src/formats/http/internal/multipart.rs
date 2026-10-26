// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict multipart parsing and bounded diagnostic summary rendering.

use std::io::Write;

use super::super::internal::AdmittedMultipart;
use super::super::internal::AdmittedMultipartBody;
use super::super::internal::MultipartSegments;
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
use crate::formats::http::inspection::inspect_form;
use crate::formats::http::inspection::inspect_json_bytes;
use crate::formats::http::inspection::inspect_ndjson;
use crate::formats::json::JsonAdmissionError;
use crate::formats::json::admit_json_text_value_at_depth;
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
pub(in crate::formats::http) fn redact(
    redactor: &FieldRedactor<'_>,
    boundary: &str,
    require_form_data: bool,
    bytes: &[u8],
    policy: &RedactionPolicy,
    max_output_bytes: usize,
    admitted: Option<&mut AdmittedMultipart>,
) -> Option<(String, bool, bool)> {
    let parts = MultipartSegments::new(bytes, boundary)?;
    if admitted
        .as_ref()
        .is_some_and(|admitted| admitted.parts.len() != parts.clone().count())
    {
        return None;
    }
    let mut admitted_parts = admitted.map(|admitted| admitted.parts.iter());
    let mut output = BoundedBodyWriter::new(max_output_bytes);
    if output.write_all(b"<multipart>\n").is_err() {
        return Some((output.into_string()?, false, true));
    }
    let mut passed = false;
    let mut has_parts = false;
    for part in parts {
        if has_parts && output.write_all(b"\n").is_err() {
            return Some((output.into_string()?, passed, true));
        }
        has_parts = true;
        let parsed = match &mut admitted_parts {
            Some(admitted_parts) => Some(admitted_parts.next()?.as_ref()),
            None => None,
        };
        let (line, part_passed, part_truncated) =
            redact_part(redactor, part, policy, require_form_data, max_output_bytes, parsed)?;
        passed |= part_passed;
        if part_truncated || output.write_all(line.as_bytes()).is_err() {
            return Some((output.into_string()?, passed, true));
        }
    }
    if admitted_parts.is_some_and(|mut parts| parts.next().is_some()) {
        return None;
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
///
/// # Returns
///
/// The admitted part data, or the parser/limit failure from a nested structured
/// part.
pub(in crate::formats::http) fn admit_structure(
    session: &mut dyn RuntimeSession,
    boundary: &str,
    require_form_data: bool,
    bytes: &[u8],
) -> Result<AdmittedMultipart, JsonAdmissionError> {
    let Some(parts) = MultipartSegments::new(bytes, boundary) else {
        return Ok(AdmittedMultipart { parts: Vec::new() });
    };
    let mut admitted = Vec::new();
    for part in parts {
        if !session.admit_format_collection_item() || !session.admit_format_node(2) {
            return Err(JsonAdmissionError::Limit);
        }
        let Some((metadata, body)) = parse_part(part, require_form_data) else {
            return Ok(AdmittedMultipart { parts: Vec::new() });
        };
        let Some(name) = metadata.name() else {
            admitted.push(None);
            continue;
        };
        if !session.admit_domain_key(name) {
            return Err(JsonAdmissionError::Limit);
        }
        if metadata.filename().is_some() || body_field_is_sensitive(session, name) {
            admitted.push(None);
            continue;
        }
        let value = match metadata.content_type() {
            Some(value) if content_type::is_json(value) => {
                let text = std::str::from_utf8(body).map_err(|_| JsonAdmissionError::Invalid)?;
                let value = admit_json_text_value_at_depth(session, text, 3)?;
                Some(AdmittedMultipartBody::Json(value))
            }
            Some(value) if content_type::is_ndjson(value) => {
                let text = std::str::from_utf8(body).map_err(|_| JsonAdmissionError::Invalid)?;
                let mut lines = super::AdmittedNdjson::new(text.ends_with('\n'));
                for line in text.lines() {
                    if json::is_blank_ndjson_line(line) {
                        lines.push_blank();
                    } else {
                        lines.push_value(admit_json_text_value_at_depth(session, line, 3)?);
                    }
                }
                Some(AdmittedMultipartBody::Ndjson(lines))
            }
            Some(value) if content_type::is_form(value) => {
                if !admit_form_fields(session, body, 3) {
                    return Err(JsonAdmissionError::Limit);
                }
                None
            }
            Some(_) | None => None,
        };
        admitted.push(value);
    }
    Ok(AdmittedMultipart { parts: admitted })
}

/// Classifies every multipart part without rendering or retaining body data.
pub(in crate::formats::http) fn inspect(
    session: &mut InspectionSession,
    boundary: &str,
    require_form_data: bool,
    bytes: &[u8],
) {
    let Some(parts) = MultipartSegments::new(bytes, boundary) else {
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
        if !session.admit_domain_key(name) {
            return;
        }
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
                if !inspect_json_bytes(session, body, 3) {
                    return;
                }
            }
            Some(value) if content_type::is_ndjson(value) => {
                if !inspect_ndjson(session, body, 3) {
                    return;
                }
            }
            Some(value) if content_type::is_form(value) => {
                inspect_form(session, body, 3);
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
///
/// # Returns
///
/// `true` when every field is admitted, or `false` when the transaction budget
/// is exhausted.
#[must_use]
pub(in crate::formats::http) fn admit_form_fields(
    session: &mut dyn RuntimeSession,
    bytes: &[u8],
    field_depth: usize,
) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let valid = form::is_valid(bytes);
    for field in bytes.split(|byte| *byte == b'&') {
        if field.is_empty() {
            continue;
        }
        if !session.admit_format_collection_item() || !session.admit_format_node(field_depth) {
            return false;
        }
        if valid
            && let Some((key, _)) = form_urlencoded::parse(field).next()
            && !session.admit_domain_key(&key)
        {
            return false;
        }
    }
    true
}

/// Resolves body rules without retaining an immutable session borrow.
///
/// # Returns
///
/// Whether `field` matches a configured sensitive-body rule.
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
///
/// # Returns
///
/// The parsed metadata and borrowed body, or `None` when required headers are
/// missing, duplicated, or malformed.
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
            let AdmittedMultipartBody::Ndjson(lines) = admitted?? else {
                return None;
            };
            let mut lines = lines.clone();
            json::redact_ndjson_values(
                redactor,
                &mut lines,
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
