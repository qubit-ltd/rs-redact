// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP URL, header, and body redaction operations.

use http::HeaderMap;
use http::HeaderValue;

use super::Redactor;
use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionTextOutput;
use crate::formats::http::BodyCapture;
use crate::formats::http::inspection;

impl Redactor {
    /// Redacts an HTTP URL through one completed text transaction.
    ///
    /// # Parameters
    ///
    /// - `value`: Raw HTTP URL, including its authority, path, query, and
    ///   fragment.
    ///
    /// # Returns
    ///
    /// Final redacted text and its execution summary, including any truncation
    /// or admission failure recorded while processing the value.
    #[must_use]
    #[inline]
    pub fn redact_http_url(&self, value: &str) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.http(|http| {
            let _ = http.url(value);
        });
        session.finish()
    }

    /// Inspects one HTTP URL without rendering it.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionInspectionError`] when the URL is invalid or a
    /// shared resource limit prevents complete inspection.
    ///
    /// # Parameters
    ///
    /// - `value`: Raw HTTP URL, including its authority, path, query, and
    ///   fragment.
    ///
    /// # Returns
    ///
    /// A conclusive sensitivity inspection, or a value-free error containing
    /// resource usage and reasons why complete classification was unavailable.
    #[inline]
    pub fn inspect_http_url(&self, value: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        inspection::inspect_url(&mut session, value);
        session.finish()
    }

    /// Redacts an HTTP header collection through one completed transaction.
    ///
    /// # Parameters
    ///
    /// - `headers`: Borrowed header collection, including repeated values.
    ///
    /// # Returns
    ///
    /// Final redacted text and its execution summary, including any truncation
    /// or admission failure recorded while processing the value.
    #[must_use]
    #[inline]
    pub fn redact_http_headers(&self, headers: &HeaderMap) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.http(|http| {
            let _ = http.headers(headers);
        });
        session.finish()
    }

    /// Inspects HTTP headers without rendering their values.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionInspectionError`] when a header cannot be decoded
    /// safely or a shared resource limit prevents complete inspection.
    ///
    /// # Parameters
    ///
    /// - `headers`: Borrowed header collection, including repeated values.
    ///
    /// # Returns
    ///
    /// A conclusive sensitivity inspection, or a value-free error containing
    /// resource usage and reasons why complete classification was unavailable.
    #[inline]
    pub fn inspect_http_headers(&self, headers: &HeaderMap) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        inspection::inspect_headers(&mut session, headers);
        session.finish()
    }

    /// Redacts one captured HTTP body through one completed session
    /// transaction.
    ///
    /// # Parameters
    ///
    /// - `capture`: Captured bytes and completeness metadata used before body
    ///   parsing.
    /// - `content_type`: Optional media-type metadata; None selects the
    ///   missing-type handling policy.
    ///
    /// # Returns
    ///
    /// Final redacted text and its execution summary, including any truncation
    /// or admission failure recorded while processing the value.
    #[must_use]
    #[inline]
    pub fn redact_http_body(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&HeaderValue>,
    ) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.http(|http| {
            let _ = http.body(capture, content_type);
        });
        session.finish()
    }

    /// Inspects one captured HTTP body without rendering it.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionInspectionError`] when capture metadata, content
    /// type, body syntax, or a shared resource limit makes inspection
    /// inconclusive.
    ///
    /// # Parameters
    ///
    /// - `capture`: Captured bytes and completeness metadata used before body
    ///   parsing.
    /// - `content_type`: Optional media-type metadata; None selects the
    ///   missing-type handling policy.
    ///
    /// # Returns
    ///
    /// A conclusive sensitivity inspection, or a value-free error containing
    /// resource usage and reasons why complete classification was unavailable.
    #[inline]
    pub fn inspect_http_body(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&HeaderValue>,
    ) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        inspection::inspect_body(&mut session, capture, content_type);
        session.finish()
    }

    /// Redacts one captured HTTP body using textual Content-Type metadata.
    ///
    /// # Parameters
    ///
    /// - `capture`: Captured bytes and completeness metadata used before body
    ///   parsing.
    /// - `content_type`: Optional media-type metadata; None selects the
    ///   missing-type handling policy.
    ///
    /// # Returns
    ///
    /// Final redacted text and its execution summary, including any truncation
    /// or admission failure recorded while processing the value.
    #[must_use]
    #[inline]
    pub fn redact_http_body_with_content_type_text(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.http(|http| {
            let _ = http.body_with_content_type_text(capture, content_type);
        });
        session.finish()
    }

    /// Inspects one captured HTTP body using textual Content-Type metadata.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionInspectionError`] when capture metadata, content
    /// type, body syntax, or a shared resource limit makes inspection
    /// inconclusive.
    ///
    /// # Parameters
    ///
    /// - `capture`: Captured bytes and completeness metadata used before body
    ///   parsing.
    /// - `content_type`: Optional media-type metadata; None selects the
    ///   missing-type handling policy.
    ///
    /// # Returns
    ///
    /// A conclusive sensitivity inspection, or a value-free error containing
    /// resource usage and reasons why complete classification was unavailable.
    #[inline]
    pub fn inspect_http_body_with_content_type_text(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        inspection::inspect_body_with_content_type_text(&mut session, capture, content_type);
        session.finish()
    }
}
