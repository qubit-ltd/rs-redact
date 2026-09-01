// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unified immutable HTTP redaction façade.
// qubit-style: allow multiple-public-types

// Owns body admission, parser dispatch, and body publication.
mod body;
// Owns diagnostic bounding and URL completion helpers.
pub(super) mod diagnostics;
// Owns application/x-www-form-urlencoded rendering.
mod form_body;
// Owns deterministic HTTP header rendering.
pub(super) mod headers;
// Owns admitted JSON and NDJSON rendering.
mod json_body;
// Owns multipart rendering after content-type selection.
mod multipart_body;
// Owns opaque text, binary, and unsupported-body fallbacks.
mod text_body;
// Owns URL parsing, nested URL traversal, and query rendering.
mod url;
// Defines the nested URL recursion ceiling.
pub(in crate::formats::http) mod url_rules;

use http::HeaderMap;
use http::HeaderValue;

use super::BodyCapture;
use super::FieldRedactor;
use super::admitted_body::AdmittedBody;
use crate::RedactionPolicy;
use crate::runtime::RenderedOperation;

/// Borrows one immutable policy while executing HTTP redaction algorithms.
///
/// This executor is deliberately private to the HTTP implementation. Session
/// adapters use the crate-private functions below so they never manufacture a
/// second redactor, session, or resource budget.
pub(in crate::formats::http) struct HttpPolicyExecutor<'policy> {
    /// The policy snapshot owned by the parent redaction session.
    policy: &'policy RedactionPolicy,
}

/// One completed HTTP rendering owned by the parent transaction.
///
/// This is deliberately an implementation detail rather than an HTTP result
/// type: HTTP never publishes a second output model. The parent transaction
/// commits its text and completion into its composer or batch publication.
pub(in crate::formats::http) struct HttpRendered {
    /// Bounded text and provenance awaiting parent-session publication.
    operation: RenderedOperation,
}

impl HttpRendered {
    /// Consumes this internal wrapper into the runtime operation
    /// representation.
    #[inline]
    pub(in crate::formats::http) fn into_operation(self) -> RenderedOperation {
        self.operation
    }
}

impl HttpPolicyExecutor<'_> {
    /// Borrows the header field-rule executor for the current operation.
    pub(super) fn header_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(self.policy.rules(), self.policy.header_rules(), self.policy.masking())
    }

    /// Borrows the query field-rule executor for the current operation.
    pub(super) fn query_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(self.policy.rules(), self.policy.query_rules(), self.policy.masking())
    }

    /// Borrows the structured-body field-rule executor for the current
    /// operation.
    pub(super) fn body_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(self.policy.rules(), self.policy.body_rules(), self.policy.masking())
    }
}

/// Parses and redacts a URL string through a parent session policy snapshot.
#[must_use]
pub(crate) fn redact_url_str_with_policy(policy: &RedactionPolicy, input: &str, output_limit: usize) -> HttpRendered {
    HttpPolicyExecutor { policy }.redact_url_str(input, output_limit)
}

/// Redacts headers through a parent session's immutable policy snapshot.
#[must_use]
pub(crate) fn redact_headers_with_policy(
    policy: &RedactionPolicy,
    headers: &HeaderMap,
    output_limit: usize,
) -> HttpRendered {
    HttpPolicyExecutor { policy }.redact_headers_with_limit(headers, output_limit)
}

/// Redacts a captured body while reusing structure built by session admission.
#[must_use]
pub(super) fn redact_admitted_body_with_policy(
    policy: &RedactionPolicy,
    capture: BodyCapture<'_>,
    content_type: Option<&HeaderValue>,
    admitted: AdmittedBody,
    output_limit: usize,
) -> HttpRendered {
    let (content_type, invalid_content_type) = match content_type {
        Some(value) => match value.to_str() {
            Ok(value) => (Some(value), false),
            Err(_) => (None, true),
        },
        None => (None, false),
    };
    HttpPolicyExecutor { policy }.redact_body_with_content_type_and_admission(
        capture,
        content_type,
        invalid_content_type,
        admitted,
        output_limit,
    )
}

/// Redacts a captured body selected by text Content-Type while reusing
/// structure built by session admission.
#[must_use]
pub(super) fn redact_admitted_body_with_content_type_text_with_policy(
    policy: &RedactionPolicy,
    capture: BodyCapture<'_>,
    content_type: Option<&str>,
    admitted: AdmittedBody,
    output_limit: usize,
) -> HttpRendered {
    HttpPolicyExecutor { policy }.redact_body_with_content_type_and_admission(
        capture,
        content_type,
        false,
        admitted,
        output_limit,
    )
}
