// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP URL, header, and body redaction operations.

use super::Redactor;
use crate::RedactionInspection;
use crate::RedactionInspectionError;
use crate::RedactionTextOutput;
use crate::formats::http::BodyCapture;

impl Redactor {
    /// Redacts an HTTP URL through one completed text transaction.
    #[must_use]
    pub fn redact_http_url(&self, value: &str) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.http(|http| {
            let _ = http.url(value);
        });
        session.finish()
    }

    /// Inspects one HTTP URL without rendering it.
    pub fn inspect_http_url(&self, value: &str) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        crate::formats::http::inspection::inspect_url(&mut session, value);
        session.finish()
    }

    /// Redacts an HTTP header collection through one completed transaction.
    #[must_use]
    pub fn redact_http_headers(&self, headers: &http::HeaderMap) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.http(|http| {
            let _ = http.headers(headers);
        });
        session.finish()
    }

    /// Inspects HTTP headers without rendering their values.
    pub fn inspect_http_headers(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        crate::formats::http::inspection::inspect_headers(&mut session, headers);
        session.finish()
    }

    /// Redacts one captured HTTP body through one completed session
    /// transaction.
    #[must_use]
    pub fn redact_http_body(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&http::HeaderValue>,
    ) -> RedactionTextOutput {
        let mut session = self.text_runtime();
        session.http(|http| {
            let _ = http.body(capture, content_type);
        });
        session.finish()
    }

    /// Inspects one captured HTTP body without rendering it.
    pub fn inspect_http_body(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&http::HeaderValue>,
    ) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        crate::formats::http::inspection::inspect_body(&mut session, capture, content_type);
        session.finish()
    }

    /// Redacts one captured HTTP body using textual Content-Type metadata.
    #[must_use]
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
    pub fn inspect_http_body_with_content_type_text(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> Result<RedactionInspection, RedactionInspectionError> {
        let mut session = self.inspection_runtime();
        crate::formats::http::inspection::inspect_body_with_content_type_text(&mut session, capture, content_type);
        session.finish()
    }
}
