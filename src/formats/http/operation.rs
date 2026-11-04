// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared HTTP admission and rendering before transaction publication.

use http::HeaderMap;
use http::HeaderValue;

use super::BodyCapture;
use super::admission::admit_body_input;
use super::admission::admit_body_structure;
use super::admission::admit_native_body_structure;
use super::admission::admit_url_structure;
use super::admission::collect_admitted_headers;
use crate::RedactionReason;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;
use crate::runtime::runtime_session::RuntimeSession;

/// Admits and renders one URL before its parent transaction publishes it.
///
/// # Parameters
///
/// - `session`: Transaction session for admission and output limits.
/// - `value`: URL text to redact.
///
/// # Returns
///
/// Rendered operation, or `None` when admission rejects the input.
pub(super) fn redact_url(session: &mut dyn RuntimeSession, value: &str) -> Option<RenderedOperation> {
    if !session.admit_input(value.len()) {
        return Some(OperationSink::truncated("<truncated>", RedactionReason::InputLimitReached).finish());
    }
    if !session.admit_format_node(1) || !admit_url_structure(session, value) {
        return Some(OperationSink::complete("<truncated>").finish());
    }
    Some(
        super::internal::http_policy_executor::redact_url_str_with_policy(
            session.policy(),
            value,
            session.remaining_output_bytes(),
        )
        .into_operation(),
    )
}

/// Admits and renders one complete header collection before publication.
///
/// # Parameters
///
/// - `session`: Transaction session for admission and output limits.
/// - `headers`: HTTP headers to redact.
///
/// # Returns
///
/// Rendered operation, or `None` when admission rejects the collection.
pub(super) fn redact_headers(session: &mut dyn RuntimeSession, headers: &HeaderMap) -> Option<RenderedOperation> {
    let headers = collect_admitted_headers(session, headers)?;
    Some(
        super::internal::http_policy_executor::redact_headers_with_policy(
            session.policy(),
            headers,
            session.remaining_output_bytes(),
        )
        .into_operation(),
    )
}

/// Admits and renders a body with native Content-Type metadata.
///
/// # Parameters
///
/// - `session`: Transaction session for admission and output limits.
/// - `capture`: Captured body and source metadata.
/// - `content_type`: Optional native Content-Type header value.
///
/// # Returns
///
/// Rendered operation, or `None` when admission rejects the input.
pub(super) fn redact_body(
    session: &mut dyn RuntimeSession,
    capture: BodyCapture<'_>,
    content_type: Option<&HeaderValue>,
) -> Option<RenderedOperation> {
    if !admit_body_input(session, capture, content_type.map(|value| value.as_bytes().len())) {
        return None;
    }
    let Some(admitted) = admit_native_body_structure(session, capture, content_type) else {
        return Some(OperationSink::complete("<truncated>").finish());
    };
    Some(
        super::internal::http_policy_executor::redact_admitted_body_with_policy(
            session.policy(),
            capture,
            admitted,
            session.remaining_output_bytes(),
        )
        .into_operation(),
    )
}

/// Admits and renders a body with textual Content-Type metadata.
///
/// # Parameters
///
/// - `session`: Transaction session for admission and output limits.
/// - `capture`: Captured body and source metadata.
/// - `content_type`: Optional textual Content-Type value.
///
/// # Returns
///
/// Rendered operation, or `None` when admission rejects the input.
pub(super) fn redact_body_with_content_type_text(
    session: &mut dyn RuntimeSession,
    capture: BodyCapture<'_>,
    content_type: Option<&str>,
) -> Option<RenderedOperation> {
    if !admit_body_input(session, capture, content_type.map(str::len)) {
        return None;
    }
    let Some(admitted) = admit_body_structure(session, capture, content_type.map(str::as_bytes)) else {
        return Some(OperationSink::complete("<truncated>").finish());
    };
    Some(
        super::internal::http_policy_executor::redact_admitted_body_with_content_type_text_with_policy(
            session.policy(),
            capture,
            admitted,
            session.remaining_output_bytes(),
        )
        .into_operation(),
    )
}
