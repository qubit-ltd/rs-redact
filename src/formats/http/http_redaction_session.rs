// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable HTTP façade over one [`RedactionSession`](crate::RedactionSession).

use http::HeaderMap;
use http::HeaderValue;
use url::Url;

use super::BodyCapture;
use super::http_redactor::url_rules;
use super::internal::nested_url;
use super::internal::nested_url::NestedUrl;
use crate::RedactedText;
use crate::RedactionHandle;
use crate::RedactionSession;

/// Feature-gated HTTP operations sharing one mutable diagnostic session.
pub struct HttpRedactionSession<'session> {
    pub(super) session: &'session mut RedactionSession,
}

impl<'session> HttpRedactionSession<'session> {
    /// Creates an HTTP facade borrowing a parent session.
    pub(crate) const fn new(session: &'session mut RedactionSession) -> Self {
        Self { session }
    }

    /// Redacts a URL string into the parent session's aggregate output.
    pub fn url(&mut self, value: &str) -> &mut Self {
        if self.session.is_output_exhausted()
            || !self.session.admit_format_node(1)
            || !self.session.admit_input(value.len())
        {
            return self;
        }
        if !self.admit_url_structure(value) {
            self.session.append_format_text(
                RedactedText::from_escaped("<truncated>"),
                crate::RedactionCompletion::Truncated,
            );
            return self;
        }
        let result = self.redact_url_str_direct(value);
        self.session.append_format_output(result.output());
        self
    }

    /// Redacts a URL as one individually resolvable transaction item.
    #[must_use]
    pub fn redact_url(&mut self, value: &str) -> RedactionHandle {
        if !self.session.is_output_exhausted()
            && self.session.admit_format_node(1)
            && self.session.admit_input(value.len())
        {
            if !self.admit_url_structure(value) {
                return self.session.stage_format_text(
                    RedactedText::from_escaped("<truncated>"),
                    crate::RedactionCompletion::Truncated,
                );
            }
            let result = self.redact_url_str_direct(value);
            return self.session.stage_item(result.into_output());
        }
        self.exhausted_handle()
    }

    /// Redacts headers into the parent session's aggregate output.
    pub fn headers(&mut self, headers: &HeaderMap) -> &mut Self {
        let Some(headers) = self.collect_admitted_headers(headers) else {
            return self;
        };
        let result = self.redact_headers_direct(&headers);
        self.session.append_format_output(result.output());
        self
    }

    /// Redacts headers as one individually resolvable transaction item.
    #[must_use]
    pub fn redact_headers(&mut self, headers: &HeaderMap) -> RedactionHandle {
        if let Some(headers) = self.collect_admitted_headers(headers) {
            let result = self.redact_headers_direct(&headers);
            return self.session.stage_item(result.into_output());
        }
        self.exhausted_handle()
    }
}

impl<'session> HttpRedactionSession<'session> {
    /// Parses and redacts one URL string.
    #[must_use]
    fn redact_url_str_direct(&mut self, text: &str) -> super::http_redactor::HttpRendered {
        super::http_redactor::redact_url_str_with_policy(
            self.session.policy(),
            text,
            self.session.remaining_output_bytes(),
        )
    }

    /// Redacts all HTTP headers.
    #[must_use]
    fn redact_headers_direct(&mut self, headers: &HeaderMap) -> super::http_redactor::HttpRendered {
        super::http_redactor::redact_headers_with_policy(
            self.session.policy(),
            headers,
            self.session.remaining_output_bytes(),
        )
    }

    /// Charges URL query traversal before the renderer parses query pairs or
    /// recursively recognizes embedded URLs. The admission pass deliberately
    /// stops at the first rejected component, so the renderer never receives
    /// a URL whose unadmitted suffix it could inspect.
    fn admit_url_structure(&mut self, text: &str) -> bool {
        let Ok(url) = Url::parse(text) else {
            return true;
        };
        self.admit_url_structure_at_depth(&url, 1)
    }

    /// Charges every query pair and recursively parsed embedded URL through
    /// the transaction-wide node, depth, and collection ledgers.
    fn admit_url_structure_at_depth(&mut self, url: &Url, url_depth: usize) -> bool {
        let Some(query) = url.query() else {
            return true;
        };
        if !super::internal::form::is_valid(query.as_bytes()) {
            return true;
        }
        for (_, value) in url.query_pairs() {
            if !self.session.admit_format_collection_item()
                || !self.session.admit_format_node(url_depth.saturating_add(1))
            {
                return false;
            }
            match nested_url::detect(value.as_ref()) {
                NestedUrl::Parsed(nested) if url_depth < url_rules::MAX_NESTED_URL_DEPTH => {
                    if !self.session.admit_format_node(url_depth.saturating_add(1))
                        || !self.admit_url_structure_at_depth(&nested, url_depth.saturating_add(1))
                    {
                        return false;
                    }
                }
                NestedUrl::NotUrl | NestedUrl::Parsed(_) | NestedUrl::Invalid | NestedUrl::LimitExceeded => {}
            }
        }
        true
    }

    /// Rebuilds only the header prefix admitted by the transaction. The
    /// source iterator stops as soon as any shared structural or input limit
    /// rejects an entry, so the renderer never observes the suffix.
    fn collect_admitted_headers(&mut self, headers: &HeaderMap) -> Option<HeaderMap> {
        if self.session.is_output_exhausted() || !self.session.admit_format_node(1) {
            return None;
        }
        let mut admitted = HeaderMap::with_capacity(headers.len());
        for (name, value) in headers {
            if !self.session.admit_format_collection_item()
                || !self.session.admit_format_node(2)
                || !self
                    .session
                    .admit_input(name.as_str().len().saturating_add(value.as_bytes().len()))
            {
                return None;
            }
            admitted.append(name.clone(), value.clone());
        }
        Some(admitted)
    }

    /// Redacts a captured HTTP body into the parent session's aggregate output.
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
    pub fn body(&mut self, capture: BodyCapture<'_>, content_type: Option<&HeaderValue>) -> &mut Self {
        if self.session.is_output_exhausted() || !self.session.admit_input(body_input_bytes(capture, content_type)) {
            return self;
        }
        if !self.admit_json_body_structure(capture, content_type.map(|value| value.as_bytes())) {
            self.session.append_format_text(
                RedactedText::from_escaped("<truncated>"),
                crate::RedactionCompletion::Truncated,
            );
            return self;
        }
        let remaining = self.session.remaining_output_bytes();
        let result = self.body_result(capture, content_type, |policy| {
            super::http_redactor::redact_body_with_policy(policy, capture, content_type, remaining)
        });
        self.session.append_format_output(result.output());
        self
    }

    /// Redacts a captured HTTP body as one individually resolvable transaction
    /// item.
    #[must_use]
    pub fn redact_body(&mut self, capture: BodyCapture<'_>, content_type: Option<&HeaderValue>) -> RedactionHandle {
        if !self.session.is_output_exhausted() && self.session.admit_input(body_input_bytes(capture, content_type)) {
            if !self.admit_json_body_structure(capture, content_type.map(|value| value.as_bytes())) {
                return self.session.stage_format_text(
                    RedactedText::from_escaped("<truncated>"),
                    crate::RedactionCompletion::Truncated,
                );
            }
            let remaining = self.session.remaining_output_bytes();
            let result = self.body_result(capture, content_type, |policy| {
                super::http_redactor::redact_body_with_policy(policy, capture, content_type, remaining)
            });
            return self.session.stage_item(result.into_output());
        }
        self.exhausted_handle()
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
    pub fn body_with_content_type_text(&mut self, capture: BodyCapture<'_>, content_type: Option<&str>) -> &mut Self {
        if self.session.is_output_exhausted()
            || !self
                .session
                .admit_input(capture.bytes().len().saturating_add(content_type.map_or(0, str::len)))
        {
            return self;
        }
        if !self.admit_json_body_structure(capture, content_type.map(str::as_bytes)) {
            self.session.append_format_text(
                RedactedText::from_escaped("<truncated>"),
                crate::RedactionCompletion::Truncated,
            );
            return self;
        }
        let remaining = self.session.remaining_output_bytes();
        let result = self.body_result(capture, None, |policy| {
            super::http_redactor::redact_body_with_content_type_text_with_policy(
                policy,
                capture,
                content_type,
                remaining,
            )
        });
        self.session.append_format_output(result.output());
        self
    }

    /// Redacts a captured HTTP body with text Content-Type as one transaction
    /// item.
    #[must_use]
    pub fn redact_body_with_content_type_text(
        &mut self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> RedactionHandle {
        let input_bytes = capture.bytes().len().saturating_add(content_type.map_or(0, str::len));
        if !self.session.is_output_exhausted() && self.session.admit_input(input_bytes) {
            if !self.admit_json_body_structure(capture, content_type.map(str::as_bytes)) {
                return self.session.stage_format_text(
                    RedactedText::from_escaped("<truncated>"),
                    crate::RedactionCompletion::Truncated,
                );
            }
            let remaining = self.session.remaining_output_bytes();
            let result = self.body_result(capture, None, |policy| {
                super::http_redactor::redact_body_with_content_type_text_with_policy(
                    policy,
                    capture,
                    content_type,
                    remaining,
                )
            });
            return self.session.stage_item(result.into_output());
        }
        self.exhausted_handle()
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
        &self,
        _capture: BodyCapture<'_>,
        _content_type: Option<&HeaderValue>,
        render: impl FnOnce(&crate::RedactionPolicy) -> super::http_redactor::HttpRendered,
    ) -> super::http_redactor::HttpRendered {
        render(self.session.policy())
    }

    /// Charges JSON-body structure before the HTTP renderer parses it. This
    /// keeps HTTP JSON bodies on the parent transaction's structural ledger
    /// instead of allocating a fresh JSON traversal budget.
    fn admit_json_body_structure(&mut self, capture: BodyCapture<'_>, content_type: Option<&[u8]>) -> bool {
        let is_json = content_type.is_some_and(|value| {
            std::str::from_utf8(value).ok().is_some_and(|value| {
                value.split(';').next().is_some_and(|media| {
                    media.trim().eq_ignore_ascii_case("application/json") || media.trim().ends_with("+json")
                })
            })
        }) || (content_type.is_none()
            && matches!(
                capture.bytes().iter().copied().find(|byte| !byte.is_ascii_whitespace()),
                Some(b'{') | Some(b'[')
            ));
        if !is_json {
            return self.session.admit_format_node(1);
        }
        let Ok(text) = std::str::from_utf8(capture.bytes()) else {
            return self.session.admit_format_node(1);
        };
        crate::formats::json::admit_json_text_structure(self.session, text)
    }

    /// Stages the standard empty output when admission is no longer possible.
    #[must_use]
    fn exhausted_handle(&mut self) -> RedactionHandle {
        self.session.stage_format_text(
            RedactedText::from_escaped(String::new()),
            crate::RedactionCompletion::Exhausted,
        )
    }
}

/// Counts bytes presented by a body operation before parser dispatch.
fn body_input_bytes(capture: BodyCapture<'_>, content_type: Option<&HeaderValue>) -> usize {
    capture
        .bytes()
        .len()
        .saturating_add(content_type.map_or(0, |value| value.as_bytes().len()))
}
