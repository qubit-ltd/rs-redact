// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable HTTP façade over one active redaction transaction.

use http::HeaderMap;
use http::HeaderValue;

use super::BodyCapture;
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Feature-gated HTTP operations sharing one mutable diagnostic session.
///
/// # Type Parameters
///
/// * `'session` - Borrow of the parent composer's unpublished transaction.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let output = Redactor::standard().text_composer().http(|http| {
///     http.url("https://example.test/?password=raw-secret");
/// }).finish();
/// assert!(!output.text().as_str().contains("raw-secret"));
/// ```
pub struct HttpRedactionWriter<'session> {
    /// Text transaction that owns policy, accounting, and aggregate output.
    pub(super) session: &'session mut TextSession,
}

impl<'session> HttpRedactionWriter<'session> {
    /// Creates an HTTP facade borrowing a parent session.
    ///
    /// # Parameters
    ///
    /// * `session` - Parent transaction receiving HTTP diagnostic operations.
    ///
    /// # Returns
    ///
    /// A writer borrowing the existing policy, accounting, and output buffer.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts a URL string into the parent session's aggregate output.
    ///
    /// # Parameters
    ///
    /// * `value` - URL text whose root, input bytes, and query structure must
    ///   pass shared admission before rendering.
    ///
    /// # Returns
    ///
    /// This writer after recording safe output and diagnostic facts.
    pub fn url(&mut self, value: &str) -> &mut Self {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        if let Some(operation) = super::operation::redact_url(self.session, value) {
            self.session.append_rendered_operation(operation);
        }
        self
    }

    /// Redacts headers into the parent session's aggregate output.
    ///
    /// # Parameters
    ///
    /// * `headers` - Borrowed headers, including native sensitive-value flags.
    ///   The entire collection must pass shared admission before rendering.
    ///
    /// # Returns
    ///
    /// This writer after appending the admitted collection or recording why
    /// it could not be rendered.
    pub fn headers(&mut self, headers: &HeaderMap) -> &mut Self {
        if let Some(operation) = super::operation::redact_headers(self.session, headers) {
            self.session.append_rendered_operation(operation);
        }
        self
    }
}

impl<'session> HttpRedactionWriter<'session> {
    /// Redacts a captured HTTP body into the parent session's aggregate output.
    ///
    /// Body and content-type byte lengths are offered to the shared budget
    /// before the body renderer inspects their contents. If input admission
    /// rejects this body, no body text is appended; the transaction summary
    /// records the rejection, and any text already appended by the composer
    /// remains. Callers can use [`crate::RedactionTextOutput::text_or_marker`]
    /// for standalone diagnostic display or
    /// [`crate::DiagnosticRedactionBatch::finish_with_marker`] for batch
    /// items. Exhausted output skips the renderer. Successful admission
    /// appends bounded output. Actual output rejection closes later
    /// operations; source truncation alone leaves any remaining output
    /// allowance usable. Structural admission failure retains its
    /// `<truncated>` diagnostic output.
    ///
    /// # Parameters
    ///
    /// * `capture` - Captured body bytes and optional source-length metadata.
    /// * `content_type` - Parsed header value used to select body handling, or
    ///   `None` to use the format's inference and fallback rules.
    ///
    /// # Returns
    ///
    /// This HTTP writer for further operations in the same transaction.
    pub fn body(&mut self, capture: BodyCapture<'_>, content_type: Option<&HeaderValue>) -> &mut Self {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        if let Some(operation) = super::operation::redact_body(self.session, capture, content_type) {
            self.session.append_rendered_operation(operation);
        }
        self
    }

    /// Redacts a captured HTTP body with text Content-Type.
    ///
    /// Body and content-type byte lengths are offered to the shared budget
    /// before the body renderer inspects their contents. If input admission
    /// rejects this body, no body text is appended; the transaction summary
    /// records the rejection, and any text already appended by the composer
    /// remains. Callers can use [`crate::RedactionTextOutput::text_or_marker`]
    /// for standalone diagnostic display or
    /// [`crate::DiagnosticRedactionBatch::finish_with_marker`] for batch
    /// items. Exhausted output skips the renderer. Successful admission
    /// appends bounded output. Actual output rejection closes later
    /// operations; source truncation alone leaves any remaining output
    /// allowance usable. Structural admission failure retains its
    /// `<truncated>` diagnostic output.
    ///
    /// # Parameters
    ///
    /// * `capture` - Captured body bytes and optional source-length metadata.
    /// * `content_type` - Text media type used to select body handling, or
    ///   `None` to use the format's inference and fallback rules.
    ///
    /// # Returns
    ///
    /// This HTTP writer for further operations in the same transaction.
    pub fn body_with_content_type_text(&mut self, capture: BodyCapture<'_>, content_type: Option<&str>) -> &mut Self {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        if let Some(operation) =
            super::operation::redact_body_with_content_type_text(self.session, capture, content_type)
        {
            self.session.append_rendered_operation(operation);
        }
        self
    }
}
