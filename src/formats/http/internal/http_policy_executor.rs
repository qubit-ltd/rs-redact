// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unified immutable HTTP redaction façade.

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

use super::AdmittedBody;
use super::HttpRendered;
use crate::RedactionPolicy;
use crate::formats::http::BodyCapture;
use crate::formats::http::FieldRedactor;

/// Borrows one immutable policy while executing HTTP redaction algorithms.
///
/// This executor is deliberately private to the HTTP implementation. Session
/// adapters use the crate-private functions below so they never manufacture a
/// second redactor, session, or resource budget.
///
/// # Type Parameters
///
/// - `'policy`: Borrow of the parent transaction’s immutable policy snapshot.
pub(in crate::formats::http) struct HttpPolicyExecutor<'policy> {
    /// The policy snapshot owned by the parent redaction session.
    policy: &'policy RedactionPolicy,
}

impl HttpPolicyExecutor<'_> {
    /// Borrows the header field-rule executor for the current operation.
    ///
    /// # Returns
    ///
    /// A borrowed classifier combining root and header rules with the shared
    /// mask policy.
    #[must_use]
    #[inline(always)]
    pub(super) fn header_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(
            self.policy.rules(),
            self.policy.http().header_rules(),
            self.policy.masking(),
        )
    }

    /// Borrows the query field-rule executor for the current operation.
    ///
    /// # Returns
    ///
    /// A borrowed classifier combining root and query and form rules with the
    /// shared mask policy.
    #[must_use]
    #[inline(always)]
    pub(super) fn query_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(
            self.policy.rules(),
            self.policy.http().query_rules(),
            self.policy.masking(),
        )
    }

    /// Borrows the structured-body field-rule executor for the current
    /// operation.
    ///
    /// # Returns
    ///
    /// A borrowed classifier combining root and structured-body rules with the
    /// shared mask policy.
    #[must_use]
    #[inline(always)]
    pub(super) fn body_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(
            self.policy.rules(),
            self.policy.http().body_rules(),
            self.policy.masking(),
        )
    }
}

/// Parses and redacts a URL string through a parent session policy snapshot.
///
/// # Parameters
///
/// - `policy`: Immutable snapshot supplied by the parent transaction.
/// - `input`: Raw URL to parse and transform.
/// - `output_limit`: Remaining bytes available for the escaped fragment.
///
/// # Returns
///
/// A bounded operation with completion and failure provenance for parent
/// publication.
#[must_use]
#[inline(always)]
pub(crate) fn redact_url_str_with_policy(policy: &RedactionPolicy, input: &str, output_limit: usize) -> HttpRendered {
    HttpPolicyExecutor { policy }.redact_url_str(input, output_limit)
}

/// Redacts headers through a parent session's immutable policy snapshot.
///
/// # Parameters
///
/// - `policy`: Immutable snapshot supplied by the parent transaction.
/// - `headers`: Admitted header collection to render deterministically.
/// - `output_limit`: Remaining bytes available for the escaped fragment.
///
/// # Returns
///
/// A bounded operation with completion and failure provenance for parent
/// publication.
#[must_use]
#[inline(always)]
pub(crate) fn redact_headers_with_policy(
    policy: &RedactionPolicy,
    headers: &HeaderMap,
    output_limit: usize,
) -> HttpRendered {
    HttpPolicyExecutor { policy }.redact_headers_with_limit(headers, output_limit)
}

/// Redacts a captured body while reusing structure built by session admission.
///
/// # Parameters
///
/// - `policy`: Immutable snapshot supplied by the parent transaction.
/// - `capture`: Captured body and completeness metadata.
/// - `content_type`: Optional media-type metadata; None preserves missing-type
///   handling.
/// - `admitted`: Parsed structure already checked by the parent transaction.
/// - `output_limit`: Remaining bytes available for the escaped fragment.
///
/// # Returns
///
/// A bounded operation with completion and failure provenance for parent
/// publication.
#[must_use]
pub(in crate::formats::http) fn redact_admitted_body_with_policy(
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
///
/// # Parameters
///
/// - `policy`: Immutable snapshot supplied by the parent transaction.
/// - `capture`: Captured body and completeness metadata.
/// - `content_type`: Optional media-type metadata; None preserves missing-type
///   handling.
/// - `admitted`: Parsed structure already checked by the parent transaction.
/// - `output_limit`: Remaining bytes available for the escaped fragment.
///
/// # Returns
///
/// A bounded operation with completion and failure provenance for parent
/// publication.
#[must_use]
#[inline(always)]
pub(in crate::formats::http) fn redact_admitted_body_with_content_type_text_with_policy(
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
