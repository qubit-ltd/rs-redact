// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable HTTP façade over one [`RedactionSession`](crate::RedactionSession).

use std::borrow::Cow;

use http::HeaderMap;
use http::HeaderValue;
use url::Url;

use super::BodyCapture;
use super::BodyRedaction;
use super::HttpRedactor;
use super::RedactedHeaders;
use super::http_redactor::headers;
use crate::RedactedText;
use crate::RedactionSession;

/// Feature-gated HTTP operations sharing one mutable diagnostic session.
pub struct HttpRedactionSession<'session, 'policy> {
    pub(super) session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> HttpRedactionSession<'session, 'policy> {
    /// Creates an HTTP facade borrowing a parent session.
    pub(crate) const fn new(session: &'session mut RedactionSession<'policy>) -> Self {
        Self { session }
    }

    /// Redacts a URL string and stages it under `key`.
    pub fn redact_url(&mut self, key: &str, value: &str) -> &mut Self {
        if !self.session.prepare_key(key) {
            return self;
        }
        let text = self.redact_url_str_direct(value);
        self.session.stage_text(key, text, crate::RedactionCompletion::Complete);
        self
    }

    /// Redacts headers and stages them under `key`.
    pub fn redact_headers(&mut self, key: &str, headers: &HeaderMap) -> &mut Self {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = self.redact_headers_direct(headers);
        self.session
            .stage_text(key, result.into_text(), crate::RedactionCompletion::Complete);
        self
    }
}

impl<'session, 'policy> HttpRedactionSession<'session, 'policy> {
    /// Creates a redactor using the session's current policy snapshot.
    #[must_use]
    fn redactor(&self) -> HttpRedactor {
        HttpRedactor::new(self.session.policy().clone())
    }

    /// Redacts a parsed URL.
    #[must_use]
    pub(crate) fn redact_url_direct(&mut self, url: &Url) -> RedactedText {
        self.redactor().redact_url(url)
    }

    /// Redacts every HTTP URL-looking token in diagnostic text.
    #[must_use]
    pub(crate) fn redact_urls_in_text_direct(&mut self, text: &str) -> RedactedText {
        self.redactor().redact_urls_in_text(text)
    }

    /// Parses and redacts one URL string.
    #[must_use]
    pub(crate) fn redact_url_str_direct(&mut self, text: &str) -> RedactedText {
        self.redactor().redact_url_str(text)
    }

    /// Redacts URL-encoded form text.
    #[must_use]
    pub(crate) fn redact_form_direct(&mut self, text: &str) -> RedactedText {
        self.redactor().redact_form(text)
    }

    /// Redacts all HTTP headers.
    #[must_use]
    pub(crate) fn redact_headers_direct(&mut self, headers: &HeaderMap) -> RedactedHeaders {
        let redactor = self.redactor();
        let mut output = String::new();
        for (name, value) in headers {
            let prefix_len = usize::from(!output.is_empty());
            let item_limit = usize::MAX.saturating_sub(prefix_len);
            let (text, _truncated) = headers::render_one(&redactor, name.as_str(), value, item_limit);
            if prefix_len != 0 {
                output.push('\n');
            }
            output.push_str(&text);
        }
        RedactedHeaders::new(RedactedText::from_escaped(Cow::Owned(output)))
    }

    /// Redacts a captured HTTP body with an optional native Content-Type.
    ///
    /// Body and content-type byte lengths are offered to the shared budget
    /// before the body renderer inspects their contents. Rejected input emits
    /// a non-empty diagnostic fallback when it fits; exhausted output returns
    /// empty text and does not invoke the renderer. Successful admission
    /// commits only the bounded output and closes the session when the body or
    /// session budget omits content.
    ///
    /// # Parameters
    ///
    /// * `capture` - Captured body bytes and optional source-length metadata.
    /// * `content_type` - Parsed header value used to select body handling.
    ///
    /// # Returns
    ///
    /// A bounded body result with completion and capture metadata.
    #[must_use]
    pub fn redact_body(&mut self, capture: BodyCapture<'_>, content_type: Option<&HeaderValue>) -> BodyRedaction {
        self.body_result(capture, content_type, |redactor| {
            redactor.redact_body_with_output_limit(capture, content_type, usize::MAX)
        })
    }

    /// Redacts a captured HTTP body with text Content-Type.
    ///
    /// Body and content-type byte lengths are offered to the shared budget
    /// before the body renderer inspects their contents. Rejected input emits
    /// a non-empty diagnostic fallback when it fits; exhausted output returns
    /// empty text and does not invoke the renderer. Successful admission
    /// commits only the bounded output and closes the session when the body or
    /// session budget omits content.
    ///
    /// # Parameters
    ///
    /// * `capture` - Captured body bytes and optional source-length metadata.
    /// * `content_type` - Text media type used to select body handling.
    ///
    /// # Returns
    ///
    /// A bounded body result with completion and capture metadata.
    #[must_use]
    pub fn redact_body_with_content_type_text(
        &mut self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> BodyRedaction {
        self.body_result(capture, None, |redactor| {
            redactor.redact_body_with_content_type_text_output_limit(capture, content_type, usize::MAX)
        })
    }

    /// Admits one body operation before calling its potentially inspecting
    /// renderer and commits its bounded output to the shared session.
    ///
    /// Fallback and exhausted admissions report zero captured bytes because
    /// `render` is skipped. A rendered body preserves its source metadata;
    /// either its own incomplete state or additional session bounding closes
    /// the session and is exposed as a truncated body result.
    #[must_use]
    fn body_result(
        &mut self,
        _capture: BodyCapture<'_>,
        _content_type: Option<&HeaderValue>,
        render: impl FnOnce(&HttpRedactor) -> BodyRedaction,
    ) -> BodyRedaction {
        let value = render(&self.redactor());
        BodyRedaction::new(
            value.text().as_str().to_owned(),
            value.status(),
            value.captured_len(),
            value.source_len(),
            value.omitted_len(),
            value.completion(),
        )
    }
}
