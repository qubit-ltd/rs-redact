// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unified immutable HTTP redaction façade.

use std::{
    borrow::Cow,
    collections::BTreeMap,
};

use http::{
    HeaderMap,
    HeaderValue,
};
use url::Url;

use crate::{
    LogSafeText,
    Redactor,
    Sensitivity,
};

use super::{
    BodyBudget,
    BodyCapture,
    BodyRedaction,
    BodyRedactionReason,
    BodyRedactionStatus,
    HttpRedactionPolicy,
    RedactedHeaders,
    TextBodyPolicy,
    UrlPathPolicy,
    internal::{
        BoundedLogWriter,
        ParsedBody,
        content_type,
        diagnostic_text,
        form,
        json,
        markers,
        multipart,
        nested_url::{
            self,
            NestedUrl,
        },
    },
};

/// Maximum number of recursively embedded HTTP URLs to redact.
const MAX_NESTED_URL_DEPTH: usize = 8;

/// Applies one immutable HTTP policy to URLs, forms, headers, and bodies.
#[must_use = "use the redactor to produce safe HTTP diagnostics"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRedactor {
    /// Complete immutable HTTP behavior snapshot.
    policy: HttpRedactionPolicy,
    /// Field redactor for headers.
    header_redactor: Redactor,
    /// Field redactor for query strings and forms.
    query_redactor: Redactor,
    /// Field redactor for structured body values.
    body_redactor: Redactor,
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
    #[inline]
    pub fn new(policy: HttpRedactionPolicy) -> Self {
        Self {
            header_redactor: Redactor::new(policy.header_policy().clone()),
            query_redactor: Redactor::new(policy.query_policy().clone()),
            body_redactor: Redactor::new(policy.body_policy().clone()),
            policy,
        }
    }

    /// Returns the immutable HTTP policy snapshot.
    ///
    /// # Returns
    ///
    /// The policy used by every operation on this redactor.
    #[inline(always)]
    pub const fn policy(&self) -> &HttpRedactionPolicy {
        &self.policy
    }

    /// Redacts a parsed URL into log-safe text.
    ///
    /// User information, passwords, fragments, sensitive query values, and
    /// non-root paths under the default policy never reach the result.
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
    pub fn redact_url(&self, url: &Url) -> LogSafeText<'static> {
        if self.diagnostic_input_exceeded(url.as_str().len()) {
            return Self::diagnostic_limit_exceeded();
        }
        self.finish_diagnostic(self.redact_url_text(url))
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
    pub fn redact_form(&self, input: &str) -> LogSafeText<'static> {
        if self.diagnostic_input_exceeded(input.len()) {
            return Self::diagnostic_limit_exceeded();
        }
        let output_limit = self.policy.diagnostic_budget().max_output_bytes();
        let text = if form::is_valid(input.as_bytes()) {
            form::redact_bounded(
                &self.query_redactor,
                input.as_bytes(),
                output_limit,
            )
        } else {
            markers::INVALID_FORM.to_string()
        };
        self.finish_diagnostic(text)
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
    pub fn redact_headers(&self, headers: &HeaderMap) -> RedactedHeaders {
        if !self.headers_fit_input_budget(headers) {
            return RedactedHeaders::new(Self::diagnostic_limit_exceeded());
        }

        let mut writer = BoundedLogWriter::new(
            self.policy.diagnostic_budget().max_output_bytes(),
            false,
        );
        let values = Self::group_header_values(headers);
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
    pub fn redact_body(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&HeaderValue>,
    ) -> BodyRedaction {
        let content_type_limit =
            self.policy.diagnostic_budget().max_input_bytes();
        let (content_type, invalid_content_type) = match content_type {
            Some(value) if value.as_bytes().len() > content_type_limit => {
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
    pub fn redact_body_with_content_type_text(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> BodyRedaction {
        let invalid_content_type = content_type.is_some_and(|value| {
            value.len() > self.policy.diagnostic_budget().max_input_bytes()
        });
        self.redact_body_with_content_type(
            capture,
            content_type,
            invalid_content_type,
        )
    }

    /// Checks the complete header input against the diagnostic budget.
    ///
    /// # Parameters
    ///
    /// * `headers` - Header map whose names and values would be inspected.
    ///
    /// # Returns
    ///
    /// `true` when every header fits within the configured input limit.
    fn headers_fit_input_budget(&self, headers: &HeaderMap) -> bool {
        let input_limit = self.policy.diagnostic_budget().max_input_bytes();
        let mut input_bytes = 0_usize;
        for (name, value) in headers {
            input_bytes = input_bytes
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len());
            if input_bytes > input_limit {
                return false;
            }
        }
        true
    }

    /// Groups repeated header values under deterministically ordered names.
    ///
    /// # Parameters
    ///
    /// * `headers` - Header map whose insertion order must be preserved within
    ///   each name.
    ///
    /// # Returns
    ///
    /// Header values grouped by their lowercase map name.
    fn group_header_values(
        headers: &HeaderMap,
    ) -> BTreeMap<&str, Vec<&HeaderValue>> {
        let mut values = BTreeMap::<&str, Vec<&HeaderValue>>::new();
        for (name, value) in headers {
            values.entry(name.as_str()).or_default().push(value);
        }
        values
    }

    /// Writes all deterministically grouped headers to a bounded writer.
    ///
    /// # Parameters
    ///
    /// * `writer` - Bounded log-safe output destination.
    /// * `values` - Ordered header groups to redact and render.
    fn write_grouped_headers(
        &self,
        writer: &mut BoundedLogWriter,
        values: BTreeMap<&str, Vec<&HeaderValue>>,
    ) {
        for (name_index, (name, header_values)) in
            values.into_iter().enumerate()
        {
            if name_index > 0 {
                let _ = writer.write_str("\n");
            }
            let _ = writer.write_str(name);
            let _ = writer.write_str(": [");
            self.write_header_values(writer, name, &header_values);
            if writer.is_full() {
                break;
            }
            let _ = writer.write_str("]");
        }
    }

    /// Redacts and writes every value for one header name.
    ///
    /// Native sensitive values always use Secret masking before name-based
    /// policy evaluation.
    ///
    /// # Parameters
    ///
    /// * `writer` - Bounded log-safe output destination.
    /// * `name` - Canonical HTTP header name.
    /// * `values` - Header values in their original map order.
    fn write_header_values(
        &self,
        writer: &mut BoundedLogWriter,
        name: &str,
        values: &[&HeaderValue],
    ) {
        for (value_index, value) in values.iter().enumerate() {
            if writer.is_full() {
                break;
            }
            if value_index > 0 {
                let _ = writer.write_str(", ");
            }
            let rendered = value.to_str().unwrap_or("<non-utf8>");
            let remaining = writer.remaining_bytes();
            if value.is_sensitive() {
                let redacted = self
                    .header_redactor
                    .policy()
                    .masking()
                    .mask_bounded(Sensitivity::Secret, rendered, remaining);
                let _ = writer.write_str(redacted.as_ref());
            } else {
                let redacted = self
                    .header_redactor
                    .redact_bounded(name, rendered, remaining);
                let _ = writer.write_str(redacted.as_str());
            }
        }
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
    fn redact_body_with_content_type(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
        invalid_content_type: bool,
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
            self.redact_body_inner(bounded, content_type, truncated)
        };
        Self::finish_body_redaction(
            parsed,
            capture,
            input_len,
            budget_truncated,
            self.policy.body_budget(),
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
        self.redact_url_text_at_depth(url, 0)
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
    fn redact_url_text_at_depth(&self, url: &Url, depth: usize) -> String {
        let output_limit = self.policy.diagnostic_budget().max_output_bytes();
        let mut output = url.clone();
        if self.policy.url_path_policy() == UrlPathPolicy::Redact
            && output.path() != "/"
        {
            output.set_path("/<redacted>");
        }
        if !output.username().is_empty() {
            let masked = self
                .query_redactor
                .policy()
                .masking()
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
                .query_redactor
                .policy()
                .masking()
                .mask_bounded(Sensitivity::Secret, password, output_limit)
                .into_owned();
            let _ = output.set_password(Some(&masked));
        }
        if let Some(fragment) = output.fragment() {
            let masked = self
                .query_redactor
                .policy()
                .masking()
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
                        .query_redactor
                        .redact_bounded(&key, &value, remaining)
                        .into_inner();
                    let value = self.redact_nested_url_value(value, depth);
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
    ) -> Cow<'a, str> {
        let raw = match value {
            Cow::Borrowed(raw) => raw,
            Cow::Owned(masked) => return Cow::Owned(masked),
        };
        match nested_url::detect(raw) {
            NestedUrl::NotUrl => Cow::Borrowed(raw),
            NestedUrl::Parsed(url) if depth < MAX_NESTED_URL_DEPTH => {
                Cow::Owned(self.redact_url_text_at_depth(&url, depth + 1))
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
    #[must_use = "redacted body text and its status must be handled together"]
    fn redact_body_inner(
        &self,
        bounded: &[u8],
        content_type: Option<&str>,
        truncated: bool,
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
                        &self.body_redactor,
                        boundary,
                        *require_form_data,
                        bounded,
                        self.policy.text_body_policy(),
                        self.policy.unkeyed_json_value_policy(),
                        self.policy.body_budget().max_output_bytes(),
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
            return self.redact_ndjson(bounded, truncated);
        }
        let trimmed = trim_ascii_whitespace(bounded);
        if matches!(&content_type, Some(content_type::ContentType::Json))
            || (content_type.is_none()
                && matches!(trimmed.first(), Some(b'{') | Some(b'[')))
        {
            return self.redact_json(bounded, truncated);
        }
        if matches!(&content_type, Some(content_type::ContentType::Form)) {
            return self.redact_body_form(bounded, truncated);
        }
        self.redact_fallback(
            bounded,
            matches!(&content_type, Some(content_type::ContentType::Text)),
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
    #[must_use = "redacted JSON text and its status must be handled together"]
    fn redact_json(&self, bounded: &[u8], truncated: bool) -> ParsedBody {
        if truncated {
            return ParsedBody::new(
                markers::INVALID_OR_TRUNCATED_JSON.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidOrTruncatedJson,
                ),
                false,
            );
        }
        let Ok(mut value) = serde_json::from_slice(bounded) else {
            return ParsedBody::new(
                markers::INVALID_JSON.to_string(),
                BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson),
                false,
            );
        };
        let passed = json::redact(
            &self.body_redactor,
            &mut value,
            self.policy.unkeyed_json_value_policy(),
            self.policy.body_budget().max_output_bytes(),
        );
        match json::serialize_bounded(
            &value,
            self.policy.body_budget().max_output_bytes(),
        ) {
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
    #[must_use = "redacted NDJSON text and its status must be handled together"]
    fn redact_ndjson(&self, bounded: &[u8], truncated: bool) -> ParsedBody {
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
            &self.body_redactor,
            bounded,
            self.policy.unkeyed_json_value_policy(),
            self.policy.body_budget().max_output_bytes(),
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
    #[must_use = "redacted form text and its status must be handled together"]
    fn redact_body_form(&self, bounded: &[u8], truncated: bool) -> ParsedBody {
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
                &self.body_redactor,
                bounded,
                self.policy.body_budget().max_output_bytes(),
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
    #[must_use = "fallback text and its status must be handled together"]
    fn redact_fallback(&self, bounded: &[u8], is_text: bool) -> ParsedBody {
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
                TextBodyPolicy::PassThrough => ParsedBody::new(
                    text.to_string(),
                    BodyRedactionStatus::PassedThrough,
                    false,
                ),
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
            truncated,
        )
    }

    /// Reports whether a diagnostic input exceeds the configured hard limit.
    ///
    /// # Parameters
    ///
    /// * `input_bytes` - Number of source bytes the operation would inspect.
    ///
    /// # Returns
    ///
    /// `true` when the input must fail closed without further processing.
    fn diagnostic_input_exceeded(&self, input_bytes: usize) -> bool {
        input_bytes > self.policy.diagnostic_budget().max_input_bytes()
    }

    /// Returns the fixed log-safe diagnostic-limit marker.
    ///
    /// # Returns
    ///
    /// A marker containing no source prefix.
    #[inline(always)]
    fn diagnostic_limit_exceeded() -> LogSafeText<'static> {
        LogSafeText::from_escaped(Cow::Borrowed(
            markers::DIAGNOSTIC_LIMIT_EXCEEDED,
        ))
    }

    /// Escapes and bounds one normally redacted HTTP diagnostic.
    ///
    /// # Parameters
    ///
    /// * `text` - Redacted diagnostic text before log escaping.
    ///
    /// # Returns
    ///
    /// Owned log-safe text within the configured output limit.
    fn finish_diagnostic(&self, text: String) -> LogSafeText<'static> {
        let mut writer = BoundedLogWriter::new(
            self.policy.diagnostic_budget().max_output_bytes(),
            false,
        );
        let _ = writer.write_str(&text);
        let (text, _) = writer.finish();
        LogSafeText::from_escaped(Cow::Owned(text))
    }
}

impl Default for HttpRedactor {
    /// Creates a redactor from the current default HTTP policy.
    ///
    /// # Returns
    ///
    /// A fail-closed redactor with finite body limits.
    fn default() -> Self {
        Self::new(HttpRedactionPolicy::default())
    }
}

/// Trims ASCII whitespace without decoding the input.
///
/// # Parameters
///
/// * `bytes` - Bytes to trim at both edges.
///
/// # Returns
///
/// A subslice without leading or trailing ASCII whitespace.
#[must_use]
fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
