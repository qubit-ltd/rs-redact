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
use super::internal::AdmittedBody;
use super::internal::http_policy_executor::url_rules;
use super::internal::nested_url;
use super::internal::nested_url::NestedUrl;
use crate::runtime::OperationSink;
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
        if !self.session.admit_input(value.len()) {
            self.session.append_rendered_operation(
                OperationSink::truncated("<truncated>", crate::RedactionReason::InputLimitReached).finish(),
            );
            return self;
        }
        if !self.session.admit_format_node(1) {
            self.session.append_rendered_operation(
                OperationSink::truncated("<truncated>", crate::RedactionReason::TraversalLimitReached).finish(),
            );
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

/// Returns `Some` with all headers after the transaction admits them.
///
/// Returns `None` if output is closed or any header fails admission; no
/// partially admitted header collection is returned.
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
    /// Redacts a captured HTTP body into the parent session's aggregate output.
    ///
    /// Body and content-type byte lengths are offered to the shared budget
    /// before the body renderer inspects their contents. Rejected input emits
    /// a non-empty diagnostic fallback when it fits; exhausted output skips
    /// the renderer. Successful admission appends bounded
    /// output. Actual output rejection closes later operations; source
    /// truncation alone leaves any remaining output allowance usable.
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
        let result = super::internal::http_policy_executor::redact_admitted_body_with_policy(
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
    /// a non-empty diagnostic fallback when it fits; exhausted output skips
    /// the renderer. Successful admission appends bounded
    /// output. Actual output rejection closes later operations; source
    /// truncation alone leaves any remaining output allowance usable.
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
        let result = super::internal::http_policy_executor::redact_admitted_body_with_content_type_text_with_policy(
            self.session.policy(),
            capture,
            content_type,
            admitted,
            remaining,
        );
        self.session.append_rendered_operation(result.into_operation());
        self
    }

    /// Parses and redacts an already admitted URL string.
    ///
    /// # Parameters
    ///
    /// * `text` - URL text admitted by the parent transaction.
    ///
    /// # Returns
    ///
    /// Unpublished HTTP output bounded by the parent's remaining bytes.
    #[must_use]
    #[inline(always)]
    fn redact_url_str_direct(&mut self, text: &str) -> super::internal::HttpRendered {
        super::internal::http_policy_executor::redact_url_str_with_policy(
            self.session.policy(),
            text,
            self.session.remaining_output_bytes(),
        )
    }

    /// Redacts an already admitted HTTP header collection.
    ///
    /// # Parameters
    ///
    /// * `headers` - Complete admitted header collection retaining sensitive
    ///   flags.
    ///
    /// # Returns
    ///
    /// Unpublished HTTP output bounded by the parent's remaining bytes.
    #[must_use]
    #[inline(always)]
    fn redact_headers_direct(&mut self, headers: &HeaderMap) -> super::internal::HttpRendered {
        super::internal::http_policy_executor::redact_headers_with_policy(
            self.session.policy(),
            headers,
            self.session.remaining_output_bytes(),
        )
    }
}

/// Parses and admits body structure once for reuse by the HTTP renderer.
///
/// Returns `Some` with retained structure or a syntax-failure classification.
/// Returns `None` when the shared structural budget rejects the body.
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
                Err(crate::formats::json::JsonAdmissionError::Limit) => {
                    return None;
                }
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
