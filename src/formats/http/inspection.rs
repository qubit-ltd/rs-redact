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
use qubit_budget::json::JsonDecodeSession;
use qubit_json::decode::JsonDecodeErrorKind;
use qubit_json::decode::JsonDecoder;
use serde_json::Value;
use url::Url;

use super::BodyCapture;
use super::FieldRedactor;
use super::TextBodyPolicy;
use super::UrlPathPolicy;
use super::internal::content_type;
use super::internal::form;
use super::internal::nested_url;
use super::internal::nested_url::NestedUrl;
use super::redaction::url_rules;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::UnkeyedJsonValuePolicy;
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
    inspect_body_with_content_type_text(session, capture, content_type);
}

/// Completely classifies one body using textual Content-Type metadata.
pub(crate) fn inspect_body_with_content_type_text(
    session: &mut InspectionSession,
    capture: BodyCapture<'_>,
    content_type: Option<&str>,
) {
    let content_type_bytes = content_type.map_or(0, str::len);
    if !session.admit_source_input(capture.total_len(), capture.captured_len())
        || !session.admit_input(content_type_bytes)
        || !session.admit_format_node(1)
    {
        return;
    }
    if capture.is_source_truncated() {
        session.fail_inspection(RedactionReason::SourceTruncated);
        return;
    }
    let bytes = capture.bytes();
    if bytes.is_empty() {
        return;
    }
    let parsed_content_type = match content_type {
        Some(value) => match content_type::parse(value) {
            Some(value) => Some(value),
            None => {
                session.fail_inspection(RedactionReason::InvalidContentType);
                return;
            }
        },
        None => None,
    };
    match parsed_content_type {
        Some(content_type::ContentType::Json) => inspect_json_bytes(session, bytes),
        Some(content_type::ContentType::Ndjson) => inspect_ndjson(session, bytes),
        Some(content_type::ContentType::Form) => inspect_form(session, bytes),
        Some(content_type::ContentType::Text) => {
            if session.policy().text_body_policy() == TextBodyPolicy::Redact {
                session.observe_sensitivity(Sensitivity::Secret);
            } else if str::from_utf8(bytes).is_err() {
                session.fail_inspection(RedactionReason::UnsupportedContentType);
            }
        }
        Some(content_type::ContentType::Multipart {
            boundary: Some(boundary),
            require_form_data,
        }) => super::internal::multipart::inspect(session, &boundary, require_form_data, bytes),
        Some(content_type::ContentType::Multipart { boundary: None, .. }) => {
            session.fail_inspection(RedactionReason::InvalidMultipart);
        }
        Some(content_type::ContentType::Other) => {
            session.fail_inspection(RedactionReason::UnsupportedContentType);
        }
        None if matches!(body_first_non_whitespace(bytes), Some(b'{') | Some(b'[')) => {
            inspect_json_bytes(session, bytes);
        }
        None => session.fail_inspection(RedactionReason::UnsupportedContentType),
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
    if session.policy().url_path_policy() == UrlPathPolicy::Redact && url.path() != "/" {
        session.observe_sensitivity(Sensitivity::High);
    }
    if let Some(query) = url.query() {
        if !form::is_valid(query.as_bytes()) {
            session.fail_inspection(RedactionReason::InvalidUri);
            return;
        }
        for (key, value) in url.query_pairs() {
            if !session.admit_format_collection_item()
                || !session.admit_format_node(depth.saturating_add(2))
            {
                return;
            }
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

/// Parses and classifies one complete JSON body.
pub(in crate::formats::http) fn inspect_json_bytes(session: &mut InspectionSession, bytes: &[u8]) {
    let decoded = {
        let budget = session.runtime_mut().json_value_budget_mut();
        let mut decoder = JsonDecoder::new(JsonDecodeSession::borrowing_value(budget));
        decoder.decode_utf8::<Value>(bytes)
    };
    match decoded {
        Ok(value) => inspect_json_value(session, &value, true),
        Err(error) if error.kind() == JsonDecodeErrorKind::Budget => {
            session.fail_inspection(RedactionReason::TraversalLimitReached);
        }
        Err(_) => session.fail_inspection(RedactionReason::InvalidJson),
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
            if unkeyed
                && session.policy().unkeyed_json_value_policy()
                    == UnkeyedJsonValuePolicy::Redact =>
        {
            session.observe_sensitivity(Sensitivity::Secret);
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Parses and classifies every non-empty NDJSON line.
pub(in crate::formats::http) fn inspect_ndjson(session: &mut InspectionSession, bytes: &[u8]) {
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        inspect_json_bytes(session, line);
    }
}

/// Parses and classifies one URL-encoded form body.
pub(in crate::formats::http) fn inspect_form(session: &mut InspectionSession, bytes: &[u8]) {
    if !form::is_valid(bytes) {
        session.fail_inspection(RedactionReason::InvalidForm);
        return;
    }
    for (key, _) in form_urlencoded::parse(bytes) {
        if !session.admit_format_collection_item() || !session.admit_format_node(2) {
            return;
        }
        if let Some(sensitivity) = body_fields(session).sensitivity(&key) {
            session.observe_sensitivity(sensitivity);
        }
    }
}

/// Returns the first non-whitespace body byte.
fn body_first_non_whitespace(bytes: &[u8]) -> Option<u8> {
    bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
}

/// Borrows HTTP query classification rules.
fn query_fields(session: &InspectionSession) -> FieldRedactor<'_> {
    FieldRedactor::new(
        session.policy().rules(),
        session.policy().query_rules(),
        session.policy().masking(),
    )
}

/// Borrows HTTP header classification rules.
fn header_fields(session: &InspectionSession) -> FieldRedactor<'_> {
    FieldRedactor::new(
        session.policy().rules(),
        session.policy().header_rules(),
        session.policy().masking(),
    )
}

/// Borrows HTTP body classification rules.
fn body_fields(session: &InspectionSession) -> FieldRedactor<'_> {
    FieldRedactor::new(
        session.policy().rules(),
        session.policy().body_rules(),
        session.policy().masking(),
    )
}
