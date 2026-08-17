// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unified immutable HTTP redaction façade.

use std::borrow::Cow;

mod body;
pub(super) mod diagnostics;
pub(super) mod headers;
mod url_rules;

use http::HeaderMap;
use http::HeaderValue;
use url::Url;

use super::BodyBudget;
use super::BodyCapture;
use super::BodyRedaction;
use super::BodyRedactionReason;
use super::BodyRedactionStatus;
use super::FieldRedactor;
use super::RedactedHeaders;
use super::TextBodyPolicy;
use super::UrlPathPolicy;
use super::internal::BoundedLogWriter;
use super::internal::ParsedBody;
use super::internal::content_type;
use super::internal::diagnostic_text;
use super::internal::form;
use super::internal::json;
use super::internal::markers;
use super::internal::multipart;
use super::internal::nested_url;
use super::internal::nested_url::NestedUrl;
use crate::LogSafeText;
use crate::RedactionPolicy;
use crate::RedactionSession;
use crate::Sensitivity;

/// Applies one immutable HTTP policy to URLs, forms, headers, and bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRedactor {
    /// Complete immutable HTTP behavior snapshot.
    policy: RedactionPolicy,
}

impl HttpRedactor {
    /// Creates a redactor from one immutable HTTP policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Complete HTTP policy snapshot.
    ///
    /// # Returns
    ///
    /// A unified HTTP redactor with independent field contexts.
    #[must_use]
    #[inline]
    pub fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }

    /// Creates a redactor with the strict policy for untrusted HTTP data.
    ///
    /// The strict snapshot masks unknown structured fields and redacts
    /// non-root URL paths while retaining the configured resource limits.
    #[must_use]
    #[inline]
    pub fn strict() -> Self {
        Self::new(RedactionPolicy::strict())
    }

    /// Returns the immutable HTTP policy snapshot.
    ///
    /// # Returns
    ///
    /// The policy used by every operation on this redactor.
    #[inline(always)]
    #[must_use]
    pub const fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Creates a mutable diagnostic session for shared HTTP operations.
    #[must_use]
    #[inline]
    pub fn session(&self) -> RedactionSession<'_> {
        RedactionSession::new(&self.policy)
    }

    /// Borrows the header field-rule executor for the current operation.
    fn header_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(
            self.policy.rules(),
            self.policy.header_rules(),
            self.policy.masking(),
        )
    }

    /// Borrows the query field-rule executor for the current operation.
    fn query_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(
            self.policy.rules(),
            self.policy.query_rules(),
            self.policy.masking(),
        )
    }

    /// Borrows the structured-body field-rule executor for the current
    /// operation.
    fn body_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(
            self.policy.rules(),
            self.policy.body_rules(),
            self.policy.masking(),
        )
    }

    /// Redacts a parsed URL into log-safe text.
    ///
    /// User information, passwords, fragments, sensitive query values, and
    /// non-root paths under a strict policy never reach the result.
    /// Complete HTTP URLs used as non-sensitive query values are redacted
    /// recursively under fixed nesting and percent-decoding limits; exceeding
    /// either limit fails closed.
    ///
    /// # Parameters
    ///
    /// * `url` - Parsed URL to redact.
    ///
    /// # Returns
    ///
    /// An owned log-safe URL representation.
    #[inline]
    #[must_use]
    pub fn redact_url(&self, url: &Url) -> LogSafeText<'static> {
        if self.diagnostic_input_exceeded(url.as_str().len()) {
            return Self::diagnostic_limit_exceeded();
        }
        self.finish_diagnostic(self.redact_url_text(url))
    }

    /// Redacts a parsed URL under an explicit output limit.
    #[must_use]
    pub(super) fn redact_url_with_output_limit(
        &self,
        url: &Url,
        output_limit: usize,
    ) -> LogSafeText<'static> {
        self.finish_diagnostic_with_limit(
            self.redact_url_text_at_depth(url, 0, output_limit),
            output_limit,
        )
    }

    /// Redacts URL-looking tokens under an explicit output limit.
    #[must_use]
    pub(super) fn redact_urls_in_text_with_output_limit(
        &self,
        text: &str,
        output_limit: usize,
    ) -> LogSafeText<'static> {
        if self.diagnostic_input_exceeded(text.len()) {
            return Self::diagnostic_limit_exceeded();
        }
        let redacted = diagnostic_text::redact_bounded(
            text,
            |url| self.redact_url_text_at_depth(url, 0, output_limit),
            output_limit,
        );
        self.finish_diagnostic_with_limit(redacted, output_limit)
    }

    /// Parses and redacts one URL string under an explicit output limit.
    #[must_use]
    pub(super) fn redact_url_str_with_output_limit(
        &self,
        input: &str,
        output_limit: usize,
    ) -> LogSafeText<'static> {
        if self.diagnostic_input_exceeded(input.len()) {
            return Self::diagnostic_limit_exceeded();
        }
        match Url::parse(input) {
            Ok(url) => self.redact_url_with_output_limit(&url, output_limit),
            Err(_) => self.finish_diagnostic_with_limit(
                markers::INVALID_URL.to_string(),
                output_limit,
            ),
        }
    }

    /// Redacts every HTTP URL-looking token in diagnostic text.
    ///
    /// Surrounding prose and punctuation are preserved. Invalid URL-looking
    /// tokens fail closed, and log-control characters are escaped once after
    /// all URL replacements are complete.
    ///
    /// # Parameters
    ///
    /// * `text` - Diagnostic text that may contain absolute HTTP URLs.
    ///
    /// # Returns
    ///
    /// Owned log-safe text with recognized URLs redacted.
    #[inline]
    #[must_use]
    pub fn redact_urls_in_text(&self, text: &str) -> LogSafeText<'static> {
        if self.diagnostic_input_exceeded(text.len()) {
            return Self::diagnostic_limit_exceeded();
        }
        let redacted =
            diagnostic_text::redact(text, |url| self.redact_url_text(url));
        self.finish_diagnostic(redacted)
    }

    /// Parses and redacts a URL, failing closed on invalid input.
    ///
    /// # Parameters
    ///
    /// * `input` - Absolute URL text.
    ///
    /// # Returns
    ///
    /// A safe redacted URL or a fixed invalid-URL marker.
    #[inline]
    #[must_use]
    pub fn redact_url_str(&self, input: &str) -> LogSafeText<'static> {
        if self.diagnostic_input_exceeded(input.len()) {
            return Self::diagnostic_limit_exceeded();
        }
        Url::parse(input).map_or_else(
            |_| self.finish_diagnostic(markers::INVALID_URL.to_string()),
            |url| self.finish_diagnostic(self.redact_url_text(&url)),
        )
    }

    /// Redacts URL-encoded form text, failing closed on ambiguity.
    ///
    /// # Parameters
    ///
    /// * `input` - URL-encoded form text.
    ///
    /// # Returns
    ///
    /// A safe redacted form or a fixed invalid-form marker.
    #[inline]
    #[must_use]
    pub fn redact_form(&self, input: &str) -> LogSafeText<'static> {
        if self.diagnostic_input_exceeded(input.len()) {
            return Self::diagnostic_limit_exceeded();
        }
        let output_limit =
            self.policy.limits().diagnostic_event().max_output_bytes();
        let text = if form::is_valid(input.as_bytes()) {
            form::redact_bounded(
                &FieldRedactor::new(
                    self.policy.rules(),
                    self.policy.query_rules(),
                    self.policy.masking(),
                ),
                input.as_bytes(),
                output_limit,
            )
        } else {
            markers::INVALID_FORM.to_string()
        };
        self.finish_diagnostic(text)
    }

    /// Redacts URL-encoded form text under an explicit output limit.
    #[must_use]
    pub(super) fn redact_form_with_output_limit(
        &self,
        input: &str,
        output_limit: usize,
    ) -> LogSafeText<'static> {
        if self.diagnostic_input_exceeded(input.len()) {
            return Self::diagnostic_limit_exceeded();
        }
        let text = if form::is_valid(input.as_bytes()) {
            form::redact_bounded(
                &FieldRedactor::new(
                    self.policy.rules(),
                    self.policy.query_rules(),
                    self.policy.masking(),
                ),
                input.as_bytes(),
                output_limit,
            )
        } else {
            markers::INVALID_FORM.to_string()
        };
        self.finish_diagnostic_with_limit(text, output_limit)
    }

    /// Redacts and deterministically renders all HTTP header values.
    ///
    /// Native sensitive values are always masked at Secret level before any
    /// name-based allow rule can apply. Non-UTF-8 values use a fixed marker.
    ///
    /// # Parameters
    ///
    /// * `headers` - HTTP header map to redact.
    ///
    /// # Returns
    ///
    /// An opaque result whose `Display` and `Debug` expose only safe text.
    #[must_use]
    pub fn redact_headers(&self, headers: &HeaderMap) -> RedactedHeaders {
        self.redact_headers_with_limit(
            headers,
            self.policy.limits().diagnostic_event().max_output_bytes(),
        )
    }

    /// Redacts headers under an explicit final output ceiling.
    #[must_use]
    pub(super) fn redact_headers_with_limit(
        &self,
        headers: &HeaderMap,
        max_output_bytes: usize,
    ) -> RedactedHeaders {
        if !self.headers_fit_input_budget(headers) {
            return RedactedHeaders::new(Self::diagnostic_limit_exceeded());
        }

        let mut writer = BoundedLogWriter::new(max_output_bytes, false);
        let values = headers::group_values(headers);
        self.write_grouped_headers(&mut writer, values);
        let (rendered, _) = writer.finish();
        RedactedHeaders::new(LogSafeText::from_escaped(Cow::Owned(rendered)))
    }

    /// Redacts a checked body capture under hard input and output limits.
    ///
    /// Parsers can observe only the prefix selected before dispatch. The final
    /// representation is escaped first and then bounded with a complete
    /// truncation marker.
    ///
    /// # Parameters
    ///
    /// * `capture` - Checked complete or source-truncated body capture.
    /// * `content_type` - Optional Content-Type used for parser selection.
    ///
    /// # Returns
    ///
    /// A bounded result exposing only log-safe text and truthful metadata.
    #[must_use]
    pub fn redact_body(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&HeaderValue>,
    ) -> BodyRedaction {
        let (content_type, invalid_content_type) = match content_type {
            Some(value)
                if self.diagnostic_input_exceeded(value.as_bytes().len()) =>
            {
                (None, true)
            }
            Some(value) => match value.to_str() {
                Ok(value) => (Some(value), false),
                Err(_) => (None, true),
            },
            None => (None, false),
        };
        self.redact_body_with_content_type(
            capture,
            content_type,
            invalid_content_type,
            self.policy.body_budget().max_output_bytes(),
        )
    }

    /// Redacts a checked body capture selected by optional Content-Type text.
    ///
    /// This accepts text from callers that do not retain a native HTTP header.
    /// Malformed Content-Type syntax is redacted fail-closed.
    ///
    /// # Parameters
    ///
    /// * `capture` - Checked complete or source-truncated body capture.
    /// * `content_type` - Optional Content-Type text used for parser selection.
    ///
    /// # Returns
    ///
    /// A bounded result exposing only log-safe text and truthful metadata.
    #[must_use]
    pub fn redact_body_with_content_type_text(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> BodyRedaction {
        let invalid_content_type = content_type
            .is_some_and(|value| self.diagnostic_input_exceeded(value.len()));
        self.redact_body_with_content_type(
            capture,
            content_type,
            invalid_content_type,
            self.policy.body_budget().max_output_bytes(),
        )
    }

    /// Redacts a body under an explicit output ceiling for a shared session.
    #[must_use]
    pub(super) fn redact_body_with_output_limit(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&HeaderValue>,
        output_limit: usize,
    ) -> BodyRedaction {
        let (content_type, invalid_content_type) = match content_type {
            Some(value)
                if self.diagnostic_input_exceeded(value.as_bytes().len()) =>
            {
                (None, true)
            }
            Some(value) => match value.to_str() {
                Ok(value) => (Some(value), false),
                Err(_) => (None, true),
            },
            None => (None, false),
        };
        self.redact_body_with_content_type(
            capture,
            content_type,
            invalid_content_type,
            output_limit,
        )
    }

    /// Redacts a body selected by text Content-Type under an explicit limit.
    #[must_use]
    pub(super) fn redact_body_with_content_type_text_output_limit(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
        output_limit: usize,
    ) -> BodyRedaction {
        let invalid_content_type = content_type
            .is_some_and(|value| self.diagnostic_input_exceeded(value.len()));
        self.redact_body_with_content_type(
            capture,
            content_type,
            invalid_content_type,
            output_limit,
        )
    }

    /// Redacts a checked body capture after normalizing Content-Type input.
    ///
    /// # Parameters
    ///
    /// * `capture` - Checked complete or source-truncated body capture.
    /// * `content_type` - UTF-8 Content-Type text available for parser
    ///   selection.
    /// * `invalid_content_type` - Whether a supplied header was non-UTF-8 or
    ///   exceeded the diagnostic input budget.
    ///
    /// # Returns
    ///
    /// A bounded result exposing only log-safe text and truthful metadata.
    #[must_use]
    fn redact_body_with_content_type(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
        invalid_content_type: bool,
        output_limit: usize,
    ) -> BodyRedaction {
        let input_len = capture
            .bytes()
            .len()
            .min(self.policy.body_budget().max_input_bytes());
        let bounded = &capture.bytes()[..input_len];
        let budget_truncated = input_len < capture.bytes().len();

        let truncated = capture.is_source_truncated() || budget_truncated;
        let parsed = if invalid_content_type {
            Self::invalid_content_type_body()
        } else {
            self.redact_body_inner(
                bounded,
                content_type,
                truncated,
                output_limit,
            )
        };
        Self::finish_body_redaction(
            parsed,
            capture,
            input_len,
            budget_truncated,
            BodyBudget::builder()
                .max_input_bytes(self.policy.body_budget().max_input_bytes())
                .max_output_bytes(output_limit)
                .build()
                .unwrap_or(self.policy.body_budget()),
        )
    }

    /// Produces an owned redacted URL before log-control escaping.
    ///
    /// # Parameters
    ///
    /// * `url` - Parsed URL to redact.
    ///
    /// # Returns
    ///
    /// An owned URL representation safe to combine with other redacted text.
    fn redact_url_text(&self, url: &Url) -> String {
        self.redact_url_text_at_depth(
            url,
            0,
            self.policy.limits().diagnostic_event().max_output_bytes(),
        )
    }

    /// Produces a redacted URL under a bounded nested-URL recursion depth.
    ///
    /// # Parameters
    ///
    /// * `url` - Parsed URL to redact.
    /// * `depth` - Number of enclosing URL query values already traversed.
    ///
    /// # Returns
    ///
    /// An owned URL representation safe to combine with other redacted text.
    fn redact_url_text_at_depth(
        &self,
        url: &Url,
        depth: usize,
        output_limit: usize,
    ) -> String {
        let mut output = url.clone();
        if self.policy.url_path_policy() == UrlPathPolicy::Redact
            && output.path() != "/"
        {
            output.set_path("/<redacted>");
        }
        if !output.username().is_empty() {
            let masked = self
                .query_field_redactor()
                .mask_bounded(
                    Sensitivity::High,
                    output.username(),
                    output_limit,
                )
                .into_owned();
            let _ = output.set_username(&masked);
        }
        if let Some(password) = output.password() {
            let masked = self
                .query_field_redactor()
                .mask_bounded(Sensitivity::Secret, password, output_limit)
                .into_owned();
            let _ = output.set_password(Some(&masked));
        }
        if let Some(fragment) = output.fragment() {
            let masked = self
                .query_field_redactor()
                .mask_bounded(Sensitivity::High, fragment, output_limit)
                .into_owned();
            output.set_fragment(Some(&masked));
        }
        if let Some(query) = url.query() {
            if form::is_valid(query.as_bytes()) {
                let query_limit = output_limit.saturating_add(1);
                let mut redacted_query = String::new();
                for (key, value) in url.query_pairs() {
                    let remaining =
                        query_limit.saturating_sub(redacted_query.len());
                    let value = self
                        .query_field_redactor()
                        .redact_bounded(&key, &value, remaining)
                        .into_inner();
                    let value = self.redact_nested_url_value(
                        value,
                        depth,
                        output_limit,
                    );
                    if !form::append_pair_bounded(
                        &mut redacted_query,
                        &key,
                        value.as_ref(),
                        query_limit,
                    ) {
                        break;
                    }
                }
                output.set_query(Some(&redacted_query));
            } else {
                output.set_query(Some(markers::INVALID_QUERY));
            }
        }
        output.to_string()
    }

    /// Redacts a complete HTTP URL embedded in a non-sensitive query value.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of any borrowed query value retained in the result.
    ///
    /// # Parameters
    ///
    /// * `value` - Query value after ordinary field-policy redaction.
    /// * `depth` - Number of enclosing URL query values already traversed.
    ///
    /// # Returns
    ///
    /// The original ownership form when no nested URL is present, otherwise
    /// an owned redacted URL or fixed fail-closed marker.
    fn redact_nested_url_value<'a>(
        &self,
        value: Cow<'a, str>,
        depth: usize,
        output_limit: usize,
    ) -> Cow<'a, str> {
        let raw = match value {
            Cow::Borrowed(raw) => raw,
            Cow::Owned(masked) => return Cow::Owned(masked),
        };
        match nested_url::detect(raw) {
            NestedUrl::NotUrl => Cow::Borrowed(raw),
            NestedUrl::Parsed(url)
                if depth < url_rules::MAX_NESTED_URL_DEPTH =>
            {
                Cow::Owned(self.redact_url_text_at_depth(
                    &url,
                    depth + 1,
                    output_limit,
                ))
            }
            NestedUrl::Parsed(_) | NestedUrl::LimitExceeded => {
                Cow::Borrowed(markers::NESTED_URL_LIMIT)
            }
            NestedUrl::Invalid => Cow::Borrowed(markers::INVALID_URL),
        }
    }

    /// Dispatches a bounded body slice to a supported parser.
    ///
    /// # Parameters
    ///
    /// * `bounded` - Input prefix already limited by the hard budget.
    /// * `content_type` - Optional parser-selection text with a checked input
    ///   bound.
    /// * `truncated` - Whether bytes are known to follow the prefix.
    ///
    /// # Returns
    ///
    /// Unescaped redacted text, outcome status, and rendering-truncation
    /// state.
    #[must_use]
    fn redact_body_inner(
        &self,
        bounded: &[u8],
        content_type: Option<&str>,
        truncated: bool,
        output_limit: usize,
    ) -> ParsedBody {
        if bounded.is_empty() {
            return ParsedBody::new(
                String::new(),
                BodyRedactionStatus::Empty,
                false,
            );
        }
        let content_type = match content_type {
            Some(value) => match content_type::parse(value) {
                Some(value) => Some(value),
                None => return Self::invalid_content_type_body(),
            },
            None => None,
        };
        if let Some(content_type::ContentType::Multipart {
            boundary,
            require_form_data,
        }) = &content_type
        {
            if truncated {
                return ParsedBody::new(
                    markers::MULTIPART_BODY.to_string(),
                    BodyRedactionStatus::Redacted(
                        BodyRedactionReason::TruncatedMultipart,
                    ),
                    false,
                );
            }
            if let Some(boundary) = boundary.as_deref()
                && let Some((text, passed, rendered_truncated)) =
                    multipart::redact(
                        &self.body_field_redactor(),
                        boundary,
                        *require_form_data,
                        bounded,
                        &self.policy,
                        output_limit,
                    )
            {
                return ParsedBody::new(
                    text,
                    if passed {
                        BodyRedactionStatus::PassedThrough
                    } else {
                        BodyRedactionStatus::Structured
                    },
                    rendered_truncated,
                );
            }
            return ParsedBody::new(
                markers::MULTIPART_BODY.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidMultipart,
                ),
                false,
            );
        }
        if matches!(&content_type, Some(content_type::ContentType::Ndjson)) {
            return self.redact_ndjson(bounded, truncated, output_limit);
        }
        let trimmed = body::trim_ascii_whitespace(bounded);
        if matches!(&content_type, Some(content_type::ContentType::Json))
            || (content_type.is_none()
                && matches!(trimmed.first(), Some(b'{') | Some(b'[')))
        {
            return self.redact_json(bounded, truncated, output_limit);
        }
        if matches!(&content_type, Some(content_type::ContentType::Form)) {
            return self.redact_body_form(bounded, truncated, output_limit);
        }
        self.redact_fallback(
            bounded,
            matches!(&content_type, Some(content_type::ContentType::Text)),
            output_limit,
        )
    }

    /// Redacts one bounded JSON document.
    ///
    /// # Parameters
    ///
    /// * `bounded` - Complete bounded JSON bytes.
    /// * `truncated` - Whether source bytes follow the prefix.
    ///
    /// # Returns
    ///
    /// Redacted JSON or a fixed fail-closed marker, status, and
    /// rendering-truncation state.
    #[must_use]
    fn redact_json(
        &self,
        bounded: &[u8],
        truncated: bool,
        output_limit: usize,
    ) -> ParsedBody {
        if truncated {
            return ParsedBody::new(
                markers::INVALID_OR_TRUNCATED_JSON.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidOrTruncatedJson,
                ),
                false,
            );
        }
        if matches!(bounded.first(), Some(b'[')) && bounded.len() > output_limit
        {
            return ParsedBody::new(
                markers::TRUNCATED.to_string(),
                BodyRedactionStatus::Structured,
                true,
            );
        }
        let Ok(mut value) = serde_json::from_slice(bounded) else {
            return ParsedBody::new(
                markers::INVALID_JSON.to_string(),
                BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson),
                false,
            );
        };
        let (passed, mask_exhausted) = json::redact(
            &self.body_field_redactor(),
            &mut value,
            self.policy.json_depth_limit(),
            self.policy.unkeyed_json_value_policy(),
            output_limit,
        );
        if mask_exhausted {
            return ParsedBody::new(
                markers::TRUNCATED.to_string(),
                BodyRedactionStatus::Structured,
                true,
            );
        }
        match json::serialize_bounded(&value, output_limit) {
            Some((text, rendered_truncated)) => ParsedBody::new(
                text,
                if passed {
                    BodyRedactionStatus::PassedThrough
                } else {
                    BodyRedactionStatus::Structured
                },
                rendered_truncated,
            ),
            None => ParsedBody::new(
                markers::INVALID_JSON.to_string(),
                BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson),
                false,
            ),
        }
    }

    /// Creates the fail-closed result for an invalid Content-Type.
    ///
    /// # Returns
    ///
    /// The fixed marker and its matching redaction status.
    #[must_use]
    fn invalid_content_type_body() -> ParsedBody {
        ParsedBody::new(
            markers::INVALID_CONTENT_TYPE.to_string(),
            BodyRedactionStatus::Redacted(
                BodyRedactionReason::InvalidContentType,
            ),
            false,
        )
    }

    /// Redacts newline-delimited JSON from a bounded slice.
    ///
    /// # Parameters
    ///
    /// * `bounded` - Complete bounded NDJSON bytes.
    /// * `truncated` - Whether source bytes follow the prefix.
    ///
    /// # Returns
    ///
    /// Redacted NDJSON or a fixed fail-closed marker, status, and
    /// rendering-truncation state.
    #[must_use]
    fn redact_ndjson(
        &self,
        bounded: &[u8],
        truncated: bool,
        output_limit: usize,
    ) -> ParsedBody {
        if truncated {
            return ParsedBody::new(
                markers::INVALID_OR_TRUNCATED_NDJSON.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidOrTruncatedNdjson,
                ),
                false,
            );
        }
        match json::redact_ndjson(
            &self.body_field_redactor(),
            bounded,
            self.policy.json_depth_limit(),
            self.policy.unkeyed_json_value_policy(),
            output_limit,
        ) {
            Some((output, passed, rendered_truncated)) => ParsedBody::new(
                output,
                if passed {
                    BodyRedactionStatus::PassedThrough
                } else {
                    BodyRedactionStatus::Structured
                },
                rendered_truncated,
            ),
            None => ParsedBody::new(
                markers::INVALID_NDJSON.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidNdjson,
                ),
                false,
            ),
        }
    }

    /// Redacts a bounded URL-encoded body.
    ///
    /// # Parameters
    ///
    /// * `bounded` - Bounded form bytes.
    /// * `truncated` - Whether source bytes follow the prefix.
    ///
    /// # Returns
    ///
    /// Redacted form text or a fixed invalid marker, status, and complete
    /// rendering state.
    #[must_use]
    fn redact_body_form(
        &self,
        bounded: &[u8],
        truncated: bool,
        output_limit: usize,
    ) -> ParsedBody {
        if truncated {
            return ParsedBody::new(
                markers::INVALID_OR_TRUNCATED_FORM.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidOrTruncatedFormUrlEncoded,
                ),
                false,
            );
        }
        if !form::is_valid(bounded) {
            return ParsedBody::new(
                markers::INVALID_FORM.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidFormUrlEncoded,
                ),
                false,
            );
        }
        ParsedBody::new(
            form::redact_bounded(
                &self.body_field_redactor(),
                bounded,
                output_limit,
            ),
            BodyRedactionStatus::Structured,
            false,
        )
    }

    /// Redacts unsupported, opaque-text, or binary bounded input.
    ///
    /// # Parameters
    ///
    /// * `bounded` - Bounded fallback bytes.
    /// * `is_text` - Whether the parsed Content-Type is an opaque text type.
    ///
    /// # Returns
    ///
    /// A policy-controlled text marker or binary summary, status, and complete
    /// rendering state.
    #[must_use]
    fn redact_fallback(
        &self,
        bounded: &[u8],
        is_text: bool,
        output_limit: usize,
    ) -> ParsedBody {
        match std::str::from_utf8(bounded) {
            Err(_) => ParsedBody::new(
                format!("<binary {} bytes>", bounded.len()),
                BodyRedactionStatus::Binary,
                false,
            ),
            Ok(text) if is_text => match self.policy.text_body_policy() {
                TextBodyPolicy::Redact => ParsedBody::new(
                    markers::TEXT_BODY.to_string(),
                    BodyRedactionStatus::Redacted(
                        BodyRedactionReason::OpaqueText,
                    ),
                    false,
                ),
                TextBodyPolicy::PassThrough => {
                    let (text, truncated) =
                        diagnostics::bound_safe_text(text, output_limit);
                    ParsedBody::new(
                        text,
                        BodyRedactionStatus::PassedThrough,
                        truncated,
                    )
                }
            },
            Ok(_) => ParsedBody::new(
                markers::UNSUPPORTED_BODY.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::UnsupportedMediaType,
                ),
                false,
            ),
        }
    }

    /// Escapes, bounds, and attaches exact source metadata to parser output.
    ///
    /// # Parameters
    ///
    /// * `parsed` - Unescaped redacted payload, status, and rendering state.
    /// * `capture` - Original checked source metadata.
    /// * `captured_len` - Number of bytes actually inspected.
    /// * `budget_truncated` - Whether the input budget omitted captured bytes.
    /// * `budget` - Hard output limit.
    ///
    /// # Returns
    ///
    /// A log-safe bounded body result with exact available metadata.
    #[must_use]
    fn finish_body_redaction(
        parsed: ParsedBody,
        capture: BodyCapture<'_>,
        captured_len: usize,
        budget_truncated: bool,
        budget: BodyBudget,
    ) -> BodyRedaction {
        let (parsed_text, status, rendered_truncated) = parsed.into_parts();
        let source_truncated = capture.is_source_truncated()
            || budget_truncated
            || rendered_truncated;
        let mut writer =
            BoundedLogWriter::new(budget.max_output_bytes(), source_truncated);
        let _ = writer.write_str(&parsed_text);
        let (text, truncated) = writer.finish();
        let source_len = capture.total_len();
        let omitted_len =
            source_len.map(|total| total.saturating_sub(captured_len));
        BodyRedaction::new(
            text,
            status,
            captured_len,
            source_len,
            omitted_len,
            if truncated {
                crate::RedactionCompletion::Truncated
            } else {
                crate::RedactionCompletion::Complete
            },
        )
    }
}

impl Default for HttpRedactor {
    /// Creates a redactor from the current default HTTP policy.
    ///
    /// # Returns
    ///
    /// A fail-closed redactor with finite body limits.
    fn default() -> Self {
        Self::new(crate::Redactor::default().policy().clone())
    }
}
