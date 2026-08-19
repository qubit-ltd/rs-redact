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
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if self.session.is_output_exhausted() {
                return self.exhausted_handle();
            }
            if !self.session.admit_format_node(1) || !self.session.admit_input(value.len()) {
                return self.stage_accounted_text(String::new());
            }
            if !self.admit_url_structure(value) {
                return self.stage_accounted_text("<truncated>");
            }
            let result = self.redact_url_str_direct(value);
            self.session.stage_item(result.into_output())
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
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
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if let Some(headers) = self.collect_admitted_headers(headers) {
                let result = self.redact_headers_direct(&headers);
                return self.session.stage_item(result.into_output());
            }
            if self.session.is_output_exhausted() {
                self.exhausted_handle()
            } else {
                self.stage_accounted_text(String::new())
            }
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
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
        if self.session.is_output_exhausted()
            || !admit_body_input(self.session, capture, content_type.map(|v| v.as_bytes().len()))
        {
            return self;
        }
        if !self.admit_body_structure(capture, content_type.map(|value| value.as_bytes())) {
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
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if self.session.is_output_exhausted() {
                return self.exhausted_handle();
            }
            if !admit_body_input(self.session, capture, content_type.map(|value| value.as_bytes().len())) {
                return self.stage_accounted_text(String::new());
            }
            if !self.admit_body_structure(capture, content_type.map(|value| value.as_bytes())) {
                return self.stage_accounted_text("<truncated>");
            }
            let remaining = self.session.remaining_output_bytes();
            let result = self.body_result(capture, content_type, |policy| {
                super::http_redactor::redact_body_with_policy(policy, capture, content_type, remaining)
            });
            self.session.stage_item(result.into_output())
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
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
        if self.session.is_output_exhausted() || !admit_body_input(self.session, capture, content_type.map(str::len)) {
            return self;
        }
        if !self.admit_body_structure(capture, content_type.map(str::as_bytes)) {
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
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if self.session.is_output_exhausted() {
                return self.exhausted_handle();
            }
            if !admit_body_input(self.session, capture, content_type.map(str::len)) {
                return self.stage_accounted_text(String::new());
            }
            if !self.admit_body_structure(capture, content_type.map(str::as_bytes)) {
                return self.stage_accounted_text("<truncated>");
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
            self.session.stage_item(result.into_output())
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
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

    /// Charges body structure before the HTTP renderer parses it. JSON and
    /// NDJSON reuse the parent transaction's JSON ledger; form fields and
    /// multipart parts use the same structural ledger before rendering.
    fn admit_body_structure(&mut self, capture: BodyCapture<'_>, content_type: Option<&[u8]>) -> bool {
        let has_content_type = content_type.is_some();
        let content_type = content_type
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(super::internal::content_type::parse);
        let inferred_json = !has_content_type
            && matches!(
                capture.bytes().iter().copied().find(|byte| !byte.is_ascii_whitespace()),
                Some(b'{') | Some(b'[')
            );
        if matches!(&content_type, Some(super::internal::content_type::ContentType::Json)) || inferred_json {
            let Ok(text) = std::str::from_utf8(capture.bytes()) else {
                return self.session.admit_format_node(1);
            };
            return crate::formats::json::admit_json_text_structure(self.session, text);
        }
        if matches!(&content_type, Some(super::internal::content_type::ContentType::Ndjson)) {
            let Ok(text) = std::str::from_utf8(capture.bytes()) else {
                return self.session.admit_format_node(1);
            };
            let mut admitted_any = false;
            for line in text.lines().filter(|line| !line.trim().is_empty()) {
                admitted_any = true;
                if !crate::formats::json::admit_json_text_structure(self.session, line) {
                    return false;
                }
            }
            return admitted_any || self.session.admit_format_node(1);
        }
        if !self.session.admit_format_node(1) {
            return false;
        }
        match content_type {
            Some(super::internal::content_type::ContentType::Form) => {
                super::internal::multipart::admit_form_fields(self.session, capture.bytes(), 2)
            }
            Some(super::internal::content_type::ContentType::Multipart {
                boundary: Some(boundary),
                require_form_data,
            }) => {
                super::internal::multipart::admit_structure(self.session, &boundary, require_form_data, capture.bytes())
            }
            Some(super::internal::content_type::ContentType::Multipart { boundary: None, .. })
            | Some(super::internal::content_type::ContentType::Text)
            | Some(super::internal::content_type::ContentType::Other)
            | None => true,
            Some(super::internal::content_type::ContentType::Json)
            | Some(super::internal::content_type::ContentType::Ndjson) => unreachable!("handled above"),
        }
    }

    /// Stages the standard empty output when admission is no longer possible.
    #[must_use]
    fn exhausted_handle(&mut self) -> RedactionHandle {
        self.session.stage_format_text(
            RedactedText::from_escaped(String::new()),
            crate::RedactionCompletion::Exhausted,
        )
    }

    /// Stages text whose completion, reasons, and usage were already recorded
    /// by the active item-accounting scope.
    #[must_use]
    fn stage_accounted_text<T>(&mut self, text: T) -> RedactionHandle
    where
        T: Into<std::borrow::Cow<'static, str>>,
    {
        self.session.stage_item(crate::RedactionOutput::new(
            RedactedText::from_escaped(text.into()),
            crate::RedactionSummary::complete(),
        ))
    }
}

/// Counts bytes presented by a body operation before parser dispatch.
fn admit_body_input(session: &mut RedactionSession, capture: BodyCapture<'_>, content_type_len: Option<usize>) -> bool {
    let content_type_len = content_type_len.unwrap_or(0);
    let inspectable = capture.bytes().len().saturating_add(content_type_len);
    let total = capture
        .total_len()
        .map(|length| length.saturating_add(content_type_len));
    session.admit_source_input(total, inspectable)
}
