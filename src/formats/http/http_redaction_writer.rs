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
use url::Url;

use super::BodyCapture;
use super::admitted_body::AdmittedBody;
use super::internal::nested_url;
use super::internal::nested_url::NestedUrl;
use super::redaction::url_rules;
use crate::runtime::OperationSink;
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Feature-gated HTTP operations sharing one mutable diagnostic session.
pub struct HttpRedactionWriter<'session> {
    /// Text transaction that owns policy, accounting, and aggregate output.
    pub(super) session: &'session mut TextSession,
}

impl<'session> HttpRedactionWriter<'session> {
    /// Creates an HTTP facade borrowing a parent session.
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts a URL string into the parent session's aggregate output.
    pub fn url(&mut self, value: &str) -> &mut Self {
        if self.session.skip_aggregate_for_exhausted_output() || !self.session.admit_format_node(1) {
            return self;
        }
        let input_was_empty = value.is_empty();
        let value = self.session.admit_input_prefix(value);
        if value.is_empty() && !input_was_empty {
            return self;
        }
        if !admit_url_structure(self.session, value) {
            self.session.append_rendered_operation(
                OperationSink::truncated("<truncated>", crate::RedactionReason::TraversalLimitReached).finish(),
            );
            return self;
        }
        let result = self.redact_url_str_direct(value);
        self.session.append_rendered_operation(result.into_operation());
        self
    }

    /// Redacts headers into the parent session's aggregate output.
    pub fn headers(&mut self, headers: &HeaderMap) -> &mut Self {
        let Some(headers) = collect_admitted_headers(self.session, headers) else {
            return self;
        };
        let result = self.redact_headers_direct(&headers);
        self.session.append_rendered_operation(result.into_operation());
        self
    }
}

/// Charges URL query traversal before rendering.
pub(crate) fn admit_url_structure(session: &mut dyn RuntimeSession, text: &str) -> bool {
    let Ok(url) = Url::parse(text) else {
        return true;
    };
    admit_url_structure_at_depth(session, &url, 1)
}

/// Charges recursively nested URL query structure.
fn admit_url_structure_at_depth(session: &mut dyn RuntimeSession, url: &Url, url_depth: usize) -> bool {
    let Some(query) = url.query() else {
        return true;
    };
    if !super::internal::form::is_valid(query.as_bytes()) {
        return true;
    }
    for (_, value) in url.query_pairs() {
        if !session.admit_format_collection_item() || !session.admit_format_node(url_depth.saturating_add(1)) {
            return false;
        }
        match nested_url::detect(value.as_ref()) {
            NestedUrl::Parsed(nested) if url_depth < url_rules::MAX_NESTED_URL_DEPTH => {
                if !session.admit_format_node(url_depth.saturating_add(1))
                    || !admit_url_structure_at_depth(session, &nested, url_depth.saturating_add(1))
                {
                    return false;
                }
            }
            NestedUrl::NotUrl | NestedUrl::Parsed(_) | NestedUrl::Invalid | NestedUrl::LimitExceeded => {}
        }
    }
    true
}

/// Rebuilds only the header prefix admitted by the transaction.
pub(crate) fn collect_admitted_headers(session: &mut dyn RuntimeSession, headers: &HeaderMap) -> Option<HeaderMap> {
    if session.skip_aggregate_for_exhausted_output() || !session.admit_format_node(1) {
        return None;
    }
    let mut admitted = HeaderMap::new();
    for (name, value) in headers {
        if !session.admit_format_collection_item()
            || !session.admit_format_node(2)
            || !session.admit_input(name.as_str().len().saturating_add(value.as_bytes().len()))
        {
            return None;
        }
        admitted.append(name.clone(), value.clone());
    }
    Some(admitted)
}

impl<'session> HttpRedactionWriter<'session> {
    /// Parses and redacts one URL string.
    #[must_use]
    fn redact_url_str_direct(&mut self, text: &str) -> super::redaction::HttpRendered {
        super::redaction::redact_url_str_with_policy(self.session.policy(), text, self.session.remaining_output_bytes())
    }

    /// Redacts all HTTP headers.
    #[must_use]
    fn redact_headers_direct(&mut self, headers: &HeaderMap) -> super::redaction::HttpRendered {
        super::redaction::redact_headers_with_policy(
            self.session.policy(),
            headers,
            self.session.remaining_output_bytes(),
        )
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
        if self.session.skip_aggregate_for_exhausted_output()
            || !admit_body_input(self.session, capture, content_type.map(|v| v.as_bytes().len()))
        {
            return self;
        }
        let Some(admitted) = admit_body_structure(self.session, capture, content_type.map(|value| value.as_bytes()))
        else {
            self.session.append_rendered_operation(
                OperationSink::truncated("<truncated>", crate::RedactionReason::TraversalLimitReached).finish(),
            );
            return self;
        };
        let remaining = self.session.remaining_output_bytes();
        let result = super::redaction::redact_admitted_body_with_policy(
            self.session.policy(),
            capture,
            content_type,
            admitted,
            remaining,
        );
        self.session.append_rendered_operation(result.into_operation());
        self
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
        if self.session.skip_aggregate_for_exhausted_output()
            || !admit_body_input(self.session, capture, content_type.map(str::len))
        {
            return self;
        }
        let Some(admitted) = admit_body_structure(self.session, capture, content_type.map(str::as_bytes)) else {
            self.session.append_rendered_operation(
                OperationSink::truncated("<truncated>", crate::RedactionReason::TraversalLimitReached).finish(),
            );
            return self;
        };
        let remaining = self.session.remaining_output_bytes();
        let result = super::redaction::redact_admitted_body_with_content_type_text_with_policy(
            self.session.policy(),
            capture,
            content_type,
            admitted,
            remaining,
        );
        self.session.append_rendered_operation(result.into_operation());
        self
    }
}

/// Charges body structure before the HTTP renderer parses it.
pub(crate) fn admit_body_structure(
    session: &mut dyn RuntimeSession,
    capture: BodyCapture<'_>,
    content_type: Option<&[u8]>,
) -> Option<AdmittedBody> {
    if session.policy().is_disabled() {
        return session.admit_format_node(1).then_some(AdmittedBody::Other);
    }
    let has_content_type = content_type.is_some();
    let content_type = content_type
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(super::internal::content_type::parse);
    let inferred_json = !has_content_type
        && matches!(
            capture.bytes().iter().copied().find(|byte| !byte.is_ascii_whitespace()),
            Some(b'{') | Some(b'[')
        );
    if capture.is_source_truncated()
        && (matches!(
            &content_type,
            Some(super::internal::content_type::ContentType::Json)
                | Some(super::internal::content_type::ContentType::Ndjson)
        ) || inferred_json)
    {
        // A captured prefix is intentionally incomplete JSON. Admit only
        // the enclosing format node and let the renderer publish the
        // invalid/truncated provenance without attempting a partial parse.
        return session.admit_format_node(1).then_some(AdmittedBody::Other);
    }
    if matches!(&content_type, Some(super::internal::content_type::ContentType::Json)) || inferred_json {
        let Ok(text) = std::str::from_utf8(capture.bytes()) else {
            return session.admit_format_node(1).then_some(AdmittedBody::InvalidJson);
        };
        return match crate::formats::json::admit_json_text_value(session, text) {
            Ok(value) => Some(AdmittedBody::Json(value)),
            Err(crate::formats::json::JsonAdmissionError::Invalid) => Some(AdmittedBody::InvalidJson),
            Err(crate::formats::json::JsonAdmissionError::Limit) => None,
        };
    }
    if matches!(&content_type, Some(super::internal::content_type::ContentType::Ndjson)) {
        let Ok(text) = std::str::from_utf8(capture.bytes()) else {
            return session.admit_format_node(1).then_some(AdmittedBody::InvalidNdjson);
        };
        let mut lines = Vec::new();
        let mut admitted_any = false;
        for line in text.lines() {
            if line.trim().is_empty() {
                lines.push(None);
                continue;
            }
            admitted_any = true;
            match crate::formats::json::admit_json_text_value(session, line) {
                Ok(value) => lines.push(Some(value)),
                Err(crate::formats::json::JsonAdmissionError::Invalid) => {
                    return Some(AdmittedBody::InvalidNdjson);
                }
                Err(crate::formats::json::JsonAdmissionError::Limit) => return None,
            }
        }
        if !admitted_any && !session.admit_format_node(1) {
            return None;
        }
        return Some(AdmittedBody::Ndjson {
            lines,
            trailing_newline: text.ends_with('\n'),
        });
    }
    if !session.admit_format_node(1) {
        return None;
    }
    let admitted = match content_type {
        Some(super::internal::content_type::ContentType::Form) => {
            super::internal::multipart::admit_form_fields(session, capture.bytes(), 2)
        }
        Some(super::internal::content_type::ContentType::Multipart {
            boundary: Some(boundary),
            require_form_data,
        }) => {
            return super::internal::multipart::admit_structure(session, &boundary, require_form_data, capture.bytes())
                .map(AdmittedBody::Multipart);
        }
        Some(super::internal::content_type::ContentType::Multipart { boundary: None, .. })
        | Some(super::internal::content_type::ContentType::Text)
        | Some(super::internal::content_type::ContentType::Other)
        | None => true,
        Some(super::internal::content_type::ContentType::Json)
        | Some(super::internal::content_type::ContentType::Ndjson) => true,
    };
    admitted.then_some(AdmittedBody::Other)
}

/// Counts bytes presented by a body operation before parser dispatch.
pub(crate) fn admit_body_input(
    session: &mut dyn RuntimeSession,
    capture: BodyCapture<'_>,
    content_type_len: Option<usize>,
) -> bool {
    let content_type_len = content_type_len.unwrap_or(0);
    let inspectable = capture.bytes().len().saturating_add(content_type_len);
    let total = capture
        .total_len()
        .map(|length| length.saturating_add(content_type_len));
    session.admit_source_input(total, inspectable)
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::BodyCapture;
    use crate::Redactor;
    use crate::formats::json::parse_counter::json_parse_count;
    use crate::formats::json::parse_counter::reset_json_parse_count;

    /// Verifies HTTP JSON admission and rendering share one parsed tree.
    #[test]
    fn enabled_http_json_body_is_parsed_exactly_once() {
        reset_json_parse_count();

        let output = Redactor::standard().redact_http_body(
            BodyCapture::complete(br#"{"token":"raw-secret"}"#),
            Some(&HeaderValue::from_static("application/json")),
        );

        assert_eq!(json_parse_count(), 1);
        assert!(!output.text().as_str().contains("raw-secret"));
    }

    /// Verifies each non-empty NDJSON line is parsed exactly once.
    #[test]
    fn enabled_http_ndjson_lines_are_parsed_exactly_once() {
        reset_json_parse_count();

        let output = Redactor::standard().redact_http_body(
            BodyCapture::complete(b"{\"token\":\"one\"}\n{\"token\":\"two\"}\n"),
            Some(&HeaderValue::from_static("application/x-ndjson")),
        );

        assert_eq!(json_parse_count(), 2);
        assert!(!output.text().as_str().contains("one"));
        assert!(!output.text().as_str().contains("two"));
    }

    /// Verifies the admitted NDJSON model retains empty source lines.
    #[test]
    fn enabled_http_ndjson_preserves_empty_lines() {
        let output = Redactor::standard().redact_http_body(
            BodyCapture::complete(b"{\"name\":\"one\"}\n\n{\"name\":\"two\"}\n"),
            Some(&HeaderValue::from_static("application/x-ndjson")),
        );

        assert_eq!(output.text().as_str(), "{\"name\":\"one\"}\\n\\n{\"name\":\"two\"}\\n",);
    }
}
