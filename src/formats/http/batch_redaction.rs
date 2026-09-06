// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Batch-only HTTP redaction.

use http::HeaderMap;
use http::HeaderValue;

use super::BodyCapture;
use super::http_redaction_writer::admit_body_input;
use super::http_redaction_writer::admit_body_structure;
use super::http_redaction_writer::admit_url_structure;
use super::http_redaction_writer::collect_admitted_headers;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;
use crate::runtime::runtime_session::RuntimeSession;

/// Redacts one URL as a batch item.
pub(crate) fn redact_url(session: &mut BatchSession, value: &str) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if !session.admit_format_node(1) {
        return session.stage_accounted_text(String::new());
    }
    let input_was_empty = value.is_empty();
    let value = session.admit_input_prefix(value);
    if value.is_empty() && !input_was_empty {
        return session.stage_accounted_text(String::new());
    }
    if !admit_url_structure(session, value) {
        return session.stage_accounted_text("<truncated>");
    }
    let result = super::redaction::redact_url_str_with_policy(
        session.policy(),
        value,
        session.remaining_output_bytes(),
    );
    session.stage_rendered_operation(result.into_operation())
}

/// Redacts headers as a batch item.
pub(crate) fn redact_headers(session: &mut BatchSession, headers: &HeaderMap) -> RedactionHandle {
    let Some(headers) = collect_admitted_headers(session, headers) else {
        return if session.is_output_exhausted() {
            session.stage_exhausted_handle()
        } else {
            session.stage_accounted_text(String::new())
        };
    };
    let result = super::redaction::redact_headers_with_policy(
        session.policy(),
        &headers,
        session.remaining_output_bytes(),
    );
    session.stage_rendered_operation(result.into_operation())
}

/// Redacts a captured body with a parsed Content-Type as a batch item.
pub(crate) fn redact_body(
    session: &mut BatchSession,
    capture: BodyCapture<'_>,
    content_type: Option<&HeaderValue>,
) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if !admit_body_input(
        session,
        capture,
        content_type.map(|value| value.as_bytes().len()),
    ) {
        return session.stage_accounted_text(String::new());
    }
    let Some(admitted) =
        admit_body_structure(session, capture, content_type.map(|value| value.as_bytes()))
    else {
        return session.stage_accounted_text("<truncated>");
    };
    let remaining = session.remaining_output_bytes();
    let result = super::redaction::redact_admitted_body_with_policy(
        session.policy(),
        capture,
        content_type,
        admitted,
        remaining,
    );
    session.stage_rendered_operation(result.into_operation())
}

/// Redacts a captured body with textual Content-Type as a batch item.
pub(crate) fn redact_body_with_content_type_text(
    session: &mut BatchSession,
    capture: BodyCapture<'_>,
    content_type: Option<&str>,
) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if !admit_body_input(session, capture, content_type.map(str::len)) {
        return session.stage_accounted_text(String::new());
    }
    let Some(admitted) = admit_body_structure(session, capture, content_type.map(str::as_bytes))
    else {
        return session.stage_accounted_text("<truncated>");
    };
    let remaining = session.remaining_output_bytes();
    let result = super::redaction::redact_admitted_body_with_content_type_text_with_policy(
        session.policy(),
        capture,
        content_type,
        admitted,
        remaining,
    );
    session.stage_rendered_operation(result.into_operation())
}
