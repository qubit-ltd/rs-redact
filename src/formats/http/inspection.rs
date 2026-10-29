// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-rendering sensitivity inspection for HTTP diagnostics.

use std::str;

use http::HeaderMap;
use http::HeaderValue;
use serde_json::Value;
use url::Url;

use super::BodyCapture;
use super::FieldRedactor;
use super::TextBodyPolicy;
use super::UrlPathPolicy;
use super::http_redaction_writer::admit_body_input;
use super::http_redaction_writer::admit_parsed_url_structure;
use super::internal::content_type;
use super::internal::form;
use super::internal::http_policy_executor::url_rules;
use super::internal::nested_url;
use super::internal::nested_url::NestedUrl;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::UnkeyedJsonValuePolicy;
use crate::formats::json::JsonAdmissionError;
use crate::formats::json::admit_json_text_value_at_depth;
use crate::runtime::InspectionSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Completely classifies one absolute HTTP URL.
pub(crate) fn inspect_url(session: &mut InspectionSession, input: &str) {
    if !session.admit_input(input.len()) || !session.admit_format_node(1) {
        return;
    }
    let Ok(url) = Url::parse(input) else {
        session.fail_inspection(RedactionReason::InvalidUri);
        return;
    };
    if !admit_parsed_url_structure(session, &url, 0) {
        return;
    }
    inspect_parsed_url(session, &url, 0);
}

/// Completely classifies one HTTP header collection.
pub(crate) fn inspect_headers(session: &mut InspectionSession, headers: &HeaderMap) {
    if !session.admit_format_node(1) {
        return;
    }
    for (name, value) in headers {
        if !session.admit_format_collection_item()
            || !session.admit_format_node(2)
            || !session.admit_domain_key(name.as_str())
            || !session.admit_input(name.as_str().len().saturating_add(value.as_bytes().len()))
        {
            return;
        }
        let sensitivity = if value.is_sensitive() {
            Some(Sensitivity::Secret)
        } else {
            header_fields(session).sensitivity(name.as_str())
        };
        if let Some(sensitivity) = sensitivity {
            session.observe_sensitivity(sensitivity);
        }
    }
}

/// Completely classifies one body using a native Content-Type header.
pub(crate) fn inspect_body(
    session: &mut InspectionSession,
    capture: BodyCapture<'_>,
    content_type: Option<&HeaderValue>,
) {
    if !admit_body_input(session, capture, content_type.map(|value| value.as_bytes().len())) {
        return;
    }
    let content_type = match content_type {
        Some(value) => match value.to_str() {
            Ok(value) => Some(value),
            Err(_) => {
                session.fail_inspection(RedactionReason::InvalidContentType);
                return;
            }
        },
        None => None,
    };
    inspect_admitted_body(session, capture, content_type);
}

/// Completely classifies one body using textual Content-Type metadata.
pub(crate) fn inspect_body_with_content_type_text(
    session: &mut InspectionSession,
    capture: BodyCapture<'_>,
    content_type: Option<&str>,
) {
    if !admit_body_input(session, capture, content_type.map(str::len)) {
        return;
    }
    inspect_admitted_body(session, capture, content_type);
}

/// Inspects a body after its captured bytes and content type have been
/// admitted.
fn inspect_admitted_body(session: &mut InspectionSession, capture: BodyCapture<'_>, content_type: Option<&str>) {
    if capture.is_source_truncated() {
        if !session.admit_format_node(1) {
            return;
        }
        session.fail_inspection(RedactionReason::SourceTruncated);
        return;
    }
    let bytes = capture.bytes();
    let parsed_content_type = match content_type {
        Some(value) => match content_type::parse(value) {
            Some(value) => Some(value),
            None => {
                if !session.admit_format_node(1) {
                    return;
                }
                session.fail_inspection(RedactionReason::InvalidContentType);
                return;
            }
        },
        None => None,
    };
    if bytes.is_empty() && !matches!(&parsed_content_type, Some(content_type::ContentType::Json)) {
        let _ = session.admit_format_node(1);
        return;
    }
    match parsed_content_type {
        Some(content_type::ContentType::Json) => {
            let _ = inspect_json_bytes(session, bytes, 1);
        }
        Some(content_type::ContentType::Ndjson) => {
            let _ = inspect_ndjson(session, bytes, 1);
        }
        Some(content_type::ContentType::Form) => {
            if session.admit_format_node(1) {
                inspect_form(session, bytes, 2);
            }
        }
        Some(content_type::ContentType::Text) => {
            if !session.admit_format_node(1) {
                return;
            }
            if session.policy().http().text_body_policy() == TextBodyPolicy::Redact {
                session.observe_sensitivity(Sensitivity::Secret);
            } else if str::from_utf8(bytes).is_err() {
                session.fail_inspection(RedactionReason::UnsupportedContentType);
            }
        }
        Some(content_type::ContentType::Multipart {
            boundary: Some(boundary),
            require_form_data,
        }) => {
            if session.admit_format_node(1) {
                super::internal::multipart::inspect(session, &boundary, require_form_data, bytes);
            }
        }
        Some(content_type::ContentType::Multipart { boundary: None, .. }) => {
            if session.admit_format_node(1) {
                session.fail_inspection(RedactionReason::InvalidMultipart);
            }
        }
        Some(content_type::ContentType::Other) => {
            if session.admit_format_node(1) {
                session.fail_inspection(RedactionReason::UnsupportedContentType);
            }
        }
        None if matches!(body_first_non_whitespace(bytes), Some(b'{') | Some(b'[')) => {
            let _ = inspect_json_bytes(session, bytes, 1);
        }
        None => {
            if session.admit_format_node(1) {
                session.fail_inspection(RedactionReason::UnsupportedContentType);
            }
        }
    }
}

/// Recursively classifies URL credentials, path, query, fragment, and nested
/// URLs.
fn inspect_parsed_url(session: &mut InspectionSession, url: &Url, depth: usize) {
    if !url.username().is_empty() {
        session.observe_sensitivity(Sensitivity::High);
    }
    if url.password().is_some() {
        session.observe_sensitivity(Sensitivity::Secret);
    }
    if session.policy().http().url_path_policy() == UrlPathPolicy::Redact && url.path() != "/" {
        session.observe_sensitivity(Sensitivity::High);
    }
    if let Some(query) = url.query() {
        if !form::is_valid(query.as_bytes()) {
            session.fail_inspection(RedactionReason::InvalidUri);
            return;
        }
        for (key, value) in url.query_pairs() {
            if let Some(sensitivity) = query_fields(session).sensitivity(&key) {
                session.observe_sensitivity(sensitivity);
                continue;
            }
            match nested_url::detect(value.as_ref()) {
                NestedUrl::Parsed(nested) if depth < url_rules::MAX_NESTED_URL_DEPTH => {
                    inspect_parsed_url(session, &nested, depth.saturating_add(1));
                }
                NestedUrl::Parsed(_) | NestedUrl::LimitExceeded => {
                    session.fail_inspection(RedactionReason::DepthLimitReached);
                    return;
                }
                NestedUrl::Invalid => {
                    session.fail_inspection(RedactionReason::InvalidUri);
                    return;
                }
                NestedUrl::NotUrl => {}
            }
        }
    }
    if url.fragment().is_some_and(|fragment| !fragment.is_empty()) {
        session.observe_sensitivity(Sensitivity::High);
    }
}

/// Admits and classifies one JSON document at the supplied root depth.
///
/// Input bytes must already be charged by the caller. Structural and JSON
/// value budgets are charged during one shared admission pass before values
/// are classified. Returns `false` after recording invalid input or an
/// exhausted budget.
pub(in crate::formats::http) fn inspect_json_bytes(
    session: &mut InspectionSession,
    bytes: &[u8],
    root_depth: usize,
) -> bool {
    let Ok(text) = str::from_utf8(bytes) else {
        session.fail_inspection(RedactionReason::InvalidJson);
        return false;
    };
    match admit_json_text_value_at_depth(session, text, root_depth) {
        Ok(value) => {
            inspect_json_value(session, &value, true);
            true
        }
        Err(JsonAdmissionError::Invalid) => {
            session.fail_inspection(RedactionReason::InvalidJson);
            false
        }
        Err(JsonAdmissionError::Limit) => false,
    }
}

/// Classifies JSON values against HTTP body-context rules.
fn inspect_json_value(session: &mut InspectionSession, value: &Value, unkeyed: bool) {
    match value {
        Value::Array(values) => {
            for value in values {
                inspect_json_value(session, value, true);
            }
        }
        Value::Object(entries) => {
            for (key, value) in entries {
                if let Some(sensitivity) = body_fields(session).sensitivity(key) {
                    session.observe_sensitivity(sensitivity);
                } else {
                    inspect_json_value(session, value, false);
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
            if unkeyed && session.policy().unkeyed_json_value_policy() == UnkeyedJsonValuePolicy::Redact =>
        {
            session.observe_sensitivity(Sensitivity::Secret);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Admits and classifies every non-empty NDJSON record at `root_depth`.
///
/// Input bytes must already be charged by the caller. Each record shares the
/// same transaction budgets. An empty top-level stream consumes one root
/// node; nested streams rely on their already admitted multipart ancestors.
/// Returns `false` after recording invalid input or an exhausted budget.
pub(in crate::formats::http) fn inspect_ndjson(
    session: &mut InspectionSession,
    bytes: &[u8],
    root_depth: usize,
) -> bool {
    let Ok(text) = str::from_utf8(bytes) else {
        session.fail_inspection(RedactionReason::InvalidJson);
        return false;
    };
    let mut any_record = false;
    for line in text.lines() {
        if super::internal::json::is_blank_ndjson_line(line) {
            continue;
        }
        any_record = true;
        if !inspect_json_bytes(session, line.as_bytes(), root_depth) {
            return false;
        }
    }
    any_record || root_depth != 1 || session.admit_format_node(1)
}

/// Parses and classifies one URL-encoded form body.
/// Completely classifies form fields at their containing structural depth.
///
/// # Parameters
///
/// * `session` - Shared inspection transaction.
/// * `bytes` - URL-encoded form body.
/// * `field_depth` - Structural depth charged to each form field.
pub(in crate::formats::http) fn inspect_form(session: &mut InspectionSession, bytes: &[u8], field_depth: usize) {
    if !super::internal::multipart::admit_form_fields(session, bytes, field_depth) {
        return;
    }
    if !form::is_valid(bytes) {
        session.fail_inspection(RedactionReason::InvalidForm);
        return;
    }
    for (key, _) in form_urlencoded::parse(bytes) {
        if let Some(sensitivity) = body_fields(session).sensitivity(&key) {
            session.observe_sensitivity(sensitivity);
        }
    }
}

/// Returns the first non-whitespace body byte.
fn body_first_non_whitespace(bytes: &[u8]) -> Option<u8> {
    bytes.iter().copied().find(|byte| !byte.is_ascii_whitespace())
}

/// Borrows HTTP query classification rules.
fn query_fields(session: &InspectionSession) -> FieldRedactor<'_> {
    FieldRedactor::new(
        session.policy().rules(),
        session.policy().http().query_rules(),
        session.policy().masking(),
    )
}

/// Borrows HTTP header classification rules.
fn header_fields(session: &InspectionSession) -> FieldRedactor<'_> {
    FieldRedactor::new(
        session.policy().rules(),
        session.policy().http().header_rules(),
        session.policy().masking(),
    )
}

/// Borrows HTTP body classification rules.
fn body_fields(session: &InspectionSession) -> FieldRedactor<'_> {
    FieldRedactor::new(
        session.policy().rules(),
        session.policy().http().body_rules(),
        session.policy().masking(),
    )
}
