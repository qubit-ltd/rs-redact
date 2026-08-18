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
use super::BodyRedactionReason;
use super::BodyRedactionStatus;
use super::HttpRedactor;
use super::RedactedHeaders;
use super::http_redactor::diagnostics::bound_safe_text;
use super::http_redactor::headers;
use super::internal::markers;
use crate::RedactedText;
use crate::RedactionCompletion;
use crate::RedactionSession;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;

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
    pub fn redact_url_as(&mut self, key: &str, value: &str) -> &mut Self {
        if !self.session.prepare_key(key) {
            return self;
        }
        let text = self.redact_url_str(value);
        self.session.stage_text(key, text, crate::RedactionCompletion::Complete);
        self
    }

    /// Redacts headers and stages them under `key`.
    pub fn redact_headers_as(&mut self, key: &str, headers: &HeaderMap) -> &mut Self {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = self.redact_headers(headers);
        self.session
            .stage_text(key, result.into_log_safe_text(), crate::RedactionCompletion::Complete);
        self
    }
}

impl<'session, 'policy> HttpRedactionSession<'session, 'policy> {
    /// Creates a redactor using the session's current policy snapshot.
    #[must_use]
    fn redactor(&self) -> HttpRedactor {
        HttpRedactor::new(self.session.policy().clone())
    }

    /// Applies one bounded HTTP rendering operation and commits its output.
    #[must_use]
    fn text_result(
        &mut self,
        input_bytes: usize,
        render: impl FnOnce(&HttpRedactor, usize) -> RedactedText,
    ) -> RedactedText {
        let policy = self.session.policy();
        let fallback = markers::DIAGNOSTIC_LIMIT_EXCEEDED;
        let domain_limit = policy.limits().diagnostic_event().max_output_bytes();
        let before = self.session.remaining_output_bytes();
        match self.session.admit(input_bytes, domain_limit, fallback.len()) {
            RedactionAdmission::Fallback => RedactedText::from_escaped(Cow::Owned(fallback.to_owned())),
            RedactionAdmission::Exhausted => RedactedText::from_escaped(Cow::Borrowed("")),
            RedactionAdmission::Render { max_output_bytes } => {
                let value = render(&self.redactor(), max_output_bytes);
                let (text, truncated): (String, bool) = bound_safe_text(value.as_str(), max_output_bytes);
                let completion = if truncated {
                    if max_output_bytes < before {
                        FragmentCompletion::DomainTruncated
                    } else {
                        FragmentCompletion::SessionTruncated
                    }
                } else {
                    FragmentCompletion::Complete
                };
                self.session.commit_output(text.len(), completion);
                RedactedText::from_escaped(Cow::Owned(text))
            }
        }
    }

    /// Redacts a parsed URL.
    #[must_use]
    pub fn redact_url(&mut self, url: &Url) -> RedactedText {
        self.text_result(url.as_str().len(), |redactor, limit| {
            redactor.redact_url_with_output_limit(url, limit)
        })
    }

    /// Redacts every HTTP URL-looking token in diagnostic text.
    #[must_use]
    pub fn redact_urls_in_text(&mut self, text: &str) -> RedactedText {
        self.text_result(text.len(), |redactor, limit| {
            redactor.redact_urls_in_text_with_output_limit(text, limit)
        })
    }

    /// Parses and redacts one URL string.
    #[must_use]
    pub fn redact_url_str(&mut self, text: &str) -> RedactedText {
        self.text_result(text.len(), |redactor, limit| {
            redactor.redact_url_str_with_output_limit(text, limit)
        })
    }

    /// Redacts URL-encoded form text.
    #[must_use]
    pub fn redact_form(&mut self, text: &str) -> RedactedText {
        self.text_result(text.len(), |redactor, limit| {
            redactor.redact_form_with_output_limit(text, limit)
        })
    }

    /// Redacts all HTTP headers.
    #[must_use]
    pub fn redact_headers(&mut self, headers: &HeaderMap) -> RedactedHeaders {
        if self.session.is_exhausted() {
            return RedactedHeaders::new(RedactedText::from_escaped(Cow::Borrowed("")));
        }
        let policy = self.session.policy();
        let fallback = markers::DIAGNOSTIC_LIMIT_EXCEEDED;
        let domain_limit = policy.limits().diagnostic_event().max_output_bytes();
        let redactor = self.redactor();
        let mut output = String::new();
        for (name, value) in headers {
            if self.session.is_exhausted() {
                break;
            }
            let input_bytes = name.as_str().len().saturating_add(value.as_bytes().len());
            let before = self.session.remaining_output_bytes();
            match self.session.admit(input_bytes, domain_limit, fallback.len()) {
                RedactionAdmission::Fallback => {
                    output.push_str(fallback);
                    break;
                }
                RedactionAdmission::Exhausted => break,
                RedactionAdmission::Render { max_output_bytes } => {
                    let prefix_len = usize::from(!output.is_empty());
                    let item_limit = max_output_bytes.saturating_sub(prefix_len);
                    let (text, truncated) = headers::render_one(&redactor, name.as_str(), value, item_limit);
                    if prefix_len != 0 {
                        output.push('\n');
                    }
                    output.push_str(&text);
                    let committed = prefix_len.saturating_add(text.len());
                    let completion = if truncated {
                        if max_output_bytes < before {
                            FragmentCompletion::DomainTruncated
                        } else {
                            FragmentCompletion::SessionTruncated
                        }
                    } else {
                        FragmentCompletion::Complete
                    };
                    self.session.commit_output(committed, completion);
                }
            }
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
        let input_bytes = capture
            .bytes()
            .len()
            .saturating_add(content_type.map_or(0, |value| value.as_bytes().len()));
        let output_limit = self.session.remaining_output_bytes();
        self.body_result(input_bytes, capture, content_type, |redactor| {
            redactor.redact_body_with_output_limit(capture, content_type, output_limit)
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
        let input_bytes = capture.bytes().len().saturating_add(content_type.map_or(0, str::len));
        let output_limit = self.session.remaining_output_bytes();
        self.body_result(input_bytes, capture, None, |redactor| {
            redactor.redact_body_with_content_type_text_output_limit(capture, content_type, output_limit)
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
        input_bytes: usize,
        capture: BodyCapture<'_>,
        _content_type: Option<&HeaderValue>,
        render: impl FnOnce(&HttpRedactor) -> BodyRedaction,
    ) -> BodyRedaction {
        let policy = self.session.policy();
        let fallback = markers::DIAGNOSTIC_LIMIT_EXCEEDED;
        let domain_limit = policy.limits().diagnostic_event().max_output_bytes();
        let before = self.session.remaining_output_bytes();
        match self.session.admit(input_bytes, domain_limit, fallback.len()) {
            RedactionAdmission::Fallback => BodyRedaction::new(
                fallback.to_owned(),
                BodyRedactionStatus::Redacted(BodyRedactionReason::DiagnosticBudgetExceeded),
                0,
                capture.total_len(),
                capture.total_len(),
                RedactionCompletion::Truncated,
            ),
            RedactionAdmission::Exhausted => BodyRedaction::new(
                String::new(),
                BodyRedactionStatus::Redacted(BodyRedactionReason::DiagnosticBudgetExceeded),
                0,
                capture.total_len(),
                capture.total_len(),
                RedactionCompletion::Exhausted,
            ),
            RedactionAdmission::Render { max_output_bytes } => {
                let value = render(&self.redactor());
                let (text, rendered_truncated): (String, bool) =
                    bound_safe_text(value.log_safe_text().as_str(), max_output_bytes);
                let body_completion = if rendered_truncated {
                    RedactionCompletion::Truncated
                } else {
                    value.completion()
                };
                let completion = if body_completion != RedactionCompletion::Complete {
                    if max_output_bytes < before {
                        FragmentCompletion::DomainTruncated
                    } else {
                        FragmentCompletion::SessionTruncated
                    }
                } else {
                    FragmentCompletion::Complete
                };
                self.session.commit_output(text.len(), completion);
                BodyRedaction::new(
                    text,
                    value.status(),
                    value.captured_len(),
                    value.source_len(),
                    value.omitted_len(),
                    body_completion,
                )
            }
        }
    }
}
