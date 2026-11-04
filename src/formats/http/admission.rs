// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared admission for HTTP redaction and inspection.

use http::HeaderMap;
use http::HeaderValue;
use url::Url;

use super::BodyCapture;
use super::internal::AdmittedBody;
use super::internal::http_policy_executor::url_rules;
use super::internal::nested_url;
use super::internal::nested_url::NestedUrl;
use crate::runtime::runtime_session::RuntimeSession;

/// Charges URL query traversal before rendering.
pub(crate) fn admit_url_structure(session: &mut dyn RuntimeSession, text: &str) -> bool {
    let Ok(url) = Url::parse(text) else {
        return true;
    };
    admit_parsed_url_structure(session, &url, 0)
}

/// Charges recursively nested URL query structure for one parsed root.
pub(in crate::formats::http) fn admit_parsed_url_structure(
    session: &mut dyn RuntimeSession,
    url: &Url,
    nested_depth: usize,
) -> bool {
    let Some(query) = url.query() else {
        return true;
    };
    if !super::internal::form::is_valid(query.as_bytes()) {
        return true;
    }
    for (key, value) in url.query_pairs() {
        let query_depth = nested_depth.saturating_add(2);
        if !session.admit_format_collection_item() || !session.admit_format_node(query_depth) {
            return false;
        }
        if !session.admit_domain_key(&key) {
            return false;
        }
        let masked_by_policy = {
            let policy = session.policy();
            !policy.is_disabled()
                && super::FieldRedactor::new(policy.rules(), policy.http().query_rules(), policy.masking())
                    .is_sensitive(&key)
        };
        if masked_by_policy {
            continue;
        }
        match nested_url::detect(value.as_ref()) {
            NestedUrl::Parsed(nested) if nested_depth < url_rules::MAX_NESTED_URL_DEPTH => {
                if !session.admit_format_node(query_depth)
                    || !admit_parsed_url_structure(session, &nested, nested_depth.saturating_add(1))
                {
                    return false;
                }
            }
            NestedUrl::NotUrl | NestedUrl::Parsed(_) | NestedUrl::Invalid | NestedUrl::LimitExceeded => {}
        }
    }
    true
}

/// Returns the original headers when the transaction admits the full
/// collection.
///
/// Admission charges are retained if output is closed or any header fails;
/// failure returns `None` without exposing a partially admitted collection.
///
/// # Parameters
///
/// * `session` - Transaction accounting and output state used for admission.
/// * `headers` - Original header collection to admit without copying it.
///
/// # Returns
///
/// A borrow of `headers` after full admission, or `None` if admission fails.
pub(crate) fn collect_admitted_headers<'headers>(
    session: &mut dyn RuntimeSession,
    headers: &'headers HeaderMap,
) -> Option<&'headers HeaderMap> {
    if session.skip_aggregate_for_exhausted_output() || !session.admit_format_node(1) {
        return None;
    }
    for (name, value) in headers {
        if !session.admit_format_collection_item()
            || !session.admit_format_node(2)
            || !session.admit_domain_key(name.as_str())
            || !session.admit_input(name.as_str().len().saturating_add(value.as_bytes().len()))
        {
            return None;
        }
    }
    Some(headers)
}

/// Parses and admits body structure once for reuse by the HTTP renderer.
///
/// Returns `Some` with retained structure or a syntax-failure classification.
/// Returns `None` when the shared structural budget rejects the body.
pub(crate) fn admit_body_structure(
    session: &mut dyn RuntimeSession,
    capture: BodyCapture<'_>,
    content_type: Option<&[u8]>,
) -> Option<AdmittedBody> {
    if session.policy().is_disabled() {
        return session.admit_format_node(1).then_some(AdmittedBody::Other(None));
    }
    let (has_content_type, content_type) = match content_type {
        Some(value) => match std::str::from_utf8(value)
            .ok()
            .and_then(super::internal::content_type::parse)
        {
            Some(content_type) => (true, Some(content_type)),
            None => {
                return session.admit_format_node(1).then_some(AdmittedBody::InvalidContentType);
            }
        },
        None => (false, None),
    };
    if capture.is_source_truncated() {
        // An incomplete body cannot provide trustworthy structure. Admit
        // only its enclosing format node and let the renderer publish the
        // source provenance without scanning the captured prefix.
        return session
            .admit_format_node(1)
            .then_some(AdmittedBody::Other(content_type));
    }
    let inferred_json = !has_content_type
        && matches!(
            capture.bytes().iter().copied().find(|byte| !byte.is_ascii_whitespace()),
            Some(b'{') | Some(b'[')
        );
    if matches!(&content_type, Some(super::internal::content_type::ContentType::Json)) || inferred_json {
        let Ok(text) = std::str::from_utf8(capture.bytes()) else {
            return session.admit_format_node(1).then_some(AdmittedBody::InvalidJson);
        };
        return match crate::formats::json::admit_json_text_value(session, text) {
            Ok(value) => Some(AdmittedBody::Json(value)),
            Err(crate::formats::json::JsonAdmissionError::Invalid) => Some(AdmittedBody::InvalidJson),
            Err(crate::formats::json::JsonAdmissionError::Limit) => None,
        };
    }
    if matches!(&content_type, Some(super::internal::content_type::ContentType::Ndjson)) {
        let Ok(text) = std::str::from_utf8(capture.bytes()) else {
            return session.admit_format_node(1).then_some(AdmittedBody::InvalidNdjson);
        };
        let mut lines = super::internal::AdmittedNdjson::new(text.ends_with('\n'));
        let mut admitted_any = false;
        for line in text.lines() {
            if super::internal::json::is_blank_ndjson_line(line) {
                lines.push_blank();
                continue;
            }
            admitted_any = true;
            match crate::formats::json::admit_json_text_value(session, line) {
                Ok(value) => lines.push_value(value),
                Err(crate::formats::json::JsonAdmissionError::Invalid) => {
                    return Some(AdmittedBody::InvalidNdjson);
                }
                Err(crate::formats::json::JsonAdmissionError::Limit) => {
                    return None;
                }
            }
        }
        if !admitted_any && !session.admit_format_node(1) {
            return None;
        }
        return Some(AdmittedBody::Ndjson(lines));
    }
    if !session.admit_format_node(1) {
        return None;
    }
    match content_type {
        Some(super::internal::content_type::ContentType::Form) => {
            if super::internal::multipart::admit_form_fields(session, capture.bytes(), 2) {
                Some(AdmittedBody::Other(Some(
                    super::internal::content_type::ContentType::Form,
                )))
            } else {
                None
            }
        }
        Some(super::internal::content_type::ContentType::Multipart {
            boundary: Some(boundary),
            require_form_data,
        }) => {
            match super::internal::multipart::admit_structure(session, &boundary, require_form_data, capture.bytes()) {
                Ok(parts) => Some(AdmittedBody::Multipart {
                    boundary,
                    require_form_data,
                    parts,
                }),
                Err(crate::formats::json::JsonAdmissionError::Invalid) => Some(AdmittedBody::InvalidMultipartJson),
                Err(crate::formats::json::JsonAdmissionError::Limit) => None,
            }
        }
        Some(value @ super::internal::content_type::ContentType::Multipart { boundary: None, .. }) => {
            Some(AdmittedBody::Other(Some(value)))
        }
        Some(
            value @ (super::internal::content_type::ContentType::Text
            | super::internal::content_type::ContentType::Other
            | super::internal::content_type::ContentType::Json
            | super::internal::content_type::ContentType::Ndjson),
        ) => Some(AdmittedBody::Other(Some(value))),
        None => Some(AdmittedBody::Other(None)),
    }
}

/// Validates native Content-Type text before admitting the captured body.
///
/// The caller must already have admitted the input bytes. Disabled policies
/// retain the existing single-node body admission without inspecting metadata.
/// An unrepresentable native header admits one format node and returns
/// `InvalidContentType`; `None` means the structural budget rejected admission.
pub(in crate::formats::http) fn admit_native_body_structure(
    session: &mut dyn RuntimeSession,
    capture: BodyCapture<'_>,
    content_type: Option<&HeaderValue>,
) -> Option<AdmittedBody> {
    if session.policy().is_disabled() {
        return admit_body_structure(session, capture, None);
    }
    match content_type.map(HeaderValue::to_str).transpose() {
        Ok(text) => admit_body_structure(session, capture, text.map(str::as_bytes)),
        Err(_) => session.admit_format_node(1).then_some(AdmittedBody::InvalidContentType),
    }
}

/// Counts bytes presented by a body operation before parser dispatch.
pub(crate) fn admit_body_input(
    session: &mut dyn RuntimeSession,
    capture: BodyCapture<'_>,
    content_type_len: Option<usize>,
) -> bool {
    if capture.is_source_truncated() {
        session.record_summary(crate::RedactionSummary::truncated(
            crate::RedactionReason::SourceTruncated,
        ));
    }
    let content_type_len = content_type_len.unwrap_or(0);
    let inspectable = capture.bytes().len().saturating_add(content_type_len);
    let total = capture
        .total_len()
        .map(|length| length.saturating_add(content_type_len));
    session.admit_source_input(total, inspectable)
}
