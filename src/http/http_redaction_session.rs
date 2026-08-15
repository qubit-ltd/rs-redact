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
use crate::LogSafeText;
use crate::RedactionSession;
use crate::policy::FragmentCompletion;
use crate::policy::RedactionAdmission;

/// Feature-gated HTTP operations sharing one mutable diagnostic session.
#[must_use = "use the session-bounded HTTP result"]
pub struct HttpRedactionSession<'session, 'policy> {
    pub(super) session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> HttpRedactionSession<'session, 'policy> {
    fn redactor(&self) -> HttpRedactor {
        HttpRedactor::new(self.session.policy().clone())
    }

    fn text_result(
        &mut self,
        input_bytes: usize,
        render: impl FnOnce(&HttpRedactor, usize) -> LogSafeText<'static>,
    ) -> LogSafeText<'static> {
        let policy = self.session.policy();
        let fallback = markers::DIAGNOSTIC_LIMIT_EXCEEDED;
        let domain_limit =
            policy.limits().diagnostic_event().max_output_bytes();
        let before = self.session.remaining_output_bytes();
        match self
            .session
            .admit(input_bytes, domain_limit, fallback.len())
        {
            RedactionAdmission::Fallback => {
                LogSafeText::from_escaped(Cow::Owned(fallback.to_owned()))
            }
            RedactionAdmission::Exhausted => {
                LogSafeText::from_escaped(Cow::Borrowed(""))
            }
            RedactionAdmission::Render { max_output_bytes } => {
                let value = render(&self.redactor(), max_output_bytes);
                let (text, truncated): (String, bool) =
                    bound_safe_text(value.as_str(), max_output_bytes);
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
                LogSafeText::from_escaped(Cow::Owned(text))
            }
        }
    }

    /// Redacts a parsed URL.
    pub fn redact_url(&mut self, url: &Url) -> LogSafeText<'static> {
        self.text_result(url.as_str().len(), |redactor, limit| {
            redactor.redact_url_with_output_limit(url, limit)
        })
    }

    /// Redacts every HTTP URL-looking token in diagnostic text.
    pub fn redact_urls_in_text(&mut self, text: &str) -> LogSafeText<'static> {
        self.text_result(text.len(), |redactor, limit| {
            redactor.redact_urls_in_text_with_output_limit(text, limit)
        })
    }

    /// Parses and redacts one URL string.
    pub fn redact_url_str(&mut self, text: &str) -> LogSafeText<'static> {
        self.text_result(text.len(), |redactor, limit| {
            redactor.redact_url_str_with_output_limit(text, limit)
        })
    }

    /// Redacts URL-encoded form text.
    pub fn redact_form(&mut self, text: &str) -> LogSafeText<'static> {
        self.text_result(text.len(), |redactor, limit| {
            redactor.redact_form_with_output_limit(text, limit)
        })
    }

    /// Redacts all HTTP headers.
    pub fn redact_headers(&mut self, headers: &HeaderMap) -> RedactedHeaders {
        if self.session.is_exhausted() {
            return RedactedHeaders::new(LogSafeText::from_escaped(
                Cow::Borrowed(""),
            ));
        }
        let policy = self.session.policy();
        let fallback = markers::DIAGNOSTIC_LIMIT_EXCEEDED;
        let domain_limit =
            policy.limits().diagnostic_event().max_output_bytes();
        let redactor = self.redactor();
        let mut output = String::new();
        for (name, value) in headers {
            if self.session.is_exhausted() {
                break;
            }
            let input_bytes =
                name.as_str().len().saturating_add(value.as_bytes().len());
            let before = self.session.remaining_output_bytes();
            match self
                .session
                .admit(input_bytes, domain_limit, fallback.len())
            {
                RedactionAdmission::Fallback => {
                    output.push_str(fallback);
                    break;
                }
                RedactionAdmission::Exhausted => break,
                RedactionAdmission::Render { max_output_bytes } => {
                    let prefix_len = usize::from(!output.is_empty());
                    let item_limit =
                        max_output_bytes.saturating_sub(prefix_len);
                    let (text, truncated) = headers::render_one(
                        &redactor,
                        name.as_str(),
                        value,
                        item_limit,
                    );
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
        RedactedHeaders::new(LogSafeText::from_escaped(Cow::Owned(output)))
    }

    /// Redacts a captured HTTP body with an optional native Content-Type.
    pub fn redact_body(
        &mut self,
        capture: BodyCapture<'_>,
        content_type: Option<&HeaderValue>,
    ) -> BodyRedaction {
        let input_bytes = capture.bytes().len().saturating_add(
            content_type.map_or(0, |value| value.as_bytes().len()),
        );
        let output_limit = self.session.remaining_output_bytes();
        self.body_result(input_bytes, capture, content_type, |redactor| {
            redactor.redact_body_with_output_limit(
                capture,
                content_type,
                output_limit,
            )
        })
    }

    /// Redacts a captured HTTP body with text Content-Type.
    pub fn redact_body_with_content_type_text(
        &mut self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> BodyRedaction {
        let input_bytes = capture
            .bytes()
            .len()
            .saturating_add(content_type.map_or(0, str::len));
        let output_limit = self.session.remaining_output_bytes();
        self.body_result(input_bytes, capture, None, |redactor| {
            redactor.redact_body_with_content_type_text_output_limit(
                capture,
                content_type,
                output_limit,
            )
        })
    }

    fn body_result(
        &mut self,
        input_bytes: usize,
        capture: BodyCapture<'_>,
        _content_type: Option<&HeaderValue>,
        render: impl FnOnce(&HttpRedactor) -> BodyRedaction,
    ) -> BodyRedaction {
        let policy = self.session.policy();
        let fallback = markers::DIAGNOSTIC_LIMIT_EXCEEDED;
        let domain_limit =
            policy.limits().diagnostic_event().max_output_bytes();
        let before = self.session.remaining_output_bytes();
        match self
            .session
            .admit(input_bytes, domain_limit, fallback.len())
        {
            RedactionAdmission::Fallback => BodyRedaction::new(
                fallback.to_owned(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::DiagnosticBudgetExceeded,
                ),
                0,
                capture.total_len(),
                capture.total_len(),
                true,
            ),
            RedactionAdmission::Exhausted => BodyRedaction::new(
                String::new(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::DiagnosticBudgetExceeded,
                ),
                0,
                capture.total_len(),
                capture.total_len(),
                true,
            ),
            RedactionAdmission::Render { max_output_bytes } => {
                let value = render(&self.redactor());
                let (text, rendered_truncated): (String, bool) =
                    bound_safe_text(
                        value.log_safe_text().as_str(),
                        max_output_bytes,
                    );
                let rendered_truncated =
                    rendered_truncated || value.is_truncated();
                let completion = if rendered_truncated {
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
                    value.is_truncated() || rendered_truncated,
                )
            }
        }
    }
}

impl<'policy> RedactionSession<'policy> {
    /// Creates the HTTP façade borrowing this session's policy and budget.
    #[inline]
    pub fn http<'session>(
        &'session mut self,
    ) -> HttpRedactionSession<'session, 'policy> {
        HttpRedactionSession { session: self }
    }
}
