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
use super::operation;
use crate::runtime::BatchSession;
use crate::runtime::RedactionHandle;

/// Redacts one URL as a batch item staged in the session.
///
/// The returned handle identifies the staged result and must be retained when
/// the caller needs to resolve that item after the batch completes.
#[must_use]
pub(crate) fn redact_url(session: &mut BatchSession, value: &str) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if let Some(rendered) = operation::redact_url(session, value) {
        session.stage_rendered_operation(rendered)
    } else {
        session.stage_accounted_text(String::new())
    }
}

/// Redacts headers as a batch item staged in the session.
///
/// The returned handle identifies the staged result and must be retained when
/// the caller needs to resolve that item after the batch completes.
#[must_use]
pub(crate) fn redact_headers(session: &mut BatchSession, headers: &HeaderMap) -> RedactionHandle {
    let Some(rendered) = operation::redact_headers(session, headers) else {
        return if session.is_output_exhausted() {
            session.stage_exhausted_handle()
        } else {
            session.stage_accounted_text(String::new())
        };
    };
    session.stage_rendered_operation(rendered)
}

/// Redacts a captured body with a parsed Content-Type as a staged batch item.
///
/// The returned handle identifies the staged result and must be retained when
/// the caller needs to resolve that item after the batch completes.
#[must_use]
pub(crate) fn redact_body(
    session: &mut BatchSession,
    capture: BodyCapture<'_>,
    content_type: Option<&HeaderValue>,
) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if let Some(rendered) = operation::redact_body(session, capture, content_type) {
        session.stage_rendered_operation(rendered)
    } else {
        session.stage_accounted_text(String::new())
    }
}

/// Redacts a captured body with textual Content-Type as a staged batch item.
///
/// The returned handle identifies the staged result and must be retained when
/// the caller needs to resolve that item after the batch completes.
#[must_use]
pub(crate) fn redact_body_with_content_type_text(
    session: &mut BatchSession,
    capture: BodyCapture<'_>,
    content_type: Option<&str>,
) -> RedactionHandle {
    if session.is_output_exhausted() {
        return session.stage_exhausted_handle();
    }
    if let Some(rendered) = operation::redact_body_with_content_type_text(session, capture, content_type) {
        session.stage_rendered_operation(rendered)
    } else {
        session.stage_accounted_text(String::new())
    }
}
