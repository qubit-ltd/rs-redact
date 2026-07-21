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
use url::{
    Url,
    form_urlencoded,
};

use crate::{
    LogSafeText,
    RedactedText,
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
        Self::safe_owned(self.redact_url_text(url))
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
        let redacted =
            diagnostic_text::redact(text, |url| self.redact_url_text(url));
        Self::safe_owned(redacted)
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
        Url::parse(input).map_or_else(
            |_| Self::safe_owned(markers::INVALID_URL.to_string()),
            |url| Self::safe_owned(self.redact_url_text(&url)),
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
        let text = if form::is_valid(input.as_bytes()) {
            form::redact(&self.query_redactor, input.as_bytes())
        } else {
            markers::INVALID_FORM.to_string()
        };
        Self::safe_owned(text)
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
        let mut values = BTreeMap::<&str, Vec<String>>::new();
        for (name, value) in headers {
            let rendered = value.to_str().unwrap_or("<non-utf8>");
            let redacted = if value.is_sensitive() {
                self.header_redactor
                    .policy()
                    .masking()
                    .mask(Sensitivity::Secret, rendered)
                    .into_owned()
            } else {
                self.header_redactor
                    .redact(name.as_str(), rendered)
                    .into_owned()
            };
            values.entry(name.as_str()).or_default().push(redacted);
        }
        let rendered = values
            .into_iter()
            .map(|(name, values)| format!("{name}: [{}]", values.join(", ")))
            .collect::<Vec<_>>()
            .join("\n");
        RedactedHeaders::new(Self::safe_owned(rendered))
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
        let input_len = capture
            .bytes()
            .len()
            .min(self.policy.body_budget().max_input_bytes());
        let bounded = &capture.bytes()[..input_len];
        let budget_truncated = input_len < capture.bytes().len();

        let parsed = self.redact_body_inner(
            bounded,
            content_type,
            capture.is_source_truncated() || budget_truncated,
        );
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
                .mask(Sensitivity::High, output.username())
                .into_owned();
            let _ = output.set_username(&masked);
        }
        if let Some(password) = output.password() {
            let masked = self
                .query_redactor
                .policy()
                .masking()
                .mask(Sensitivity::Secret, password)
                .into_owned();
            let _ = output.set_password(Some(&masked));
        }
        if let Some(fragment) = output.fragment() {
            let masked = self
                .query_redactor
                .policy()
                .masking()
                .mask(Sensitivity::High, fragment)
                .into_owned();
            output.set_fragment(Some(&masked));
        }
        if let Some(query) = url.query() {
            if form::is_valid(query.as_bytes()) {
                let mut serializer =
                    form_urlencoded::Serializer::new(String::new());
                for (key, value) in url.query_pairs() {
                    let value =
                        self.query_redactor.redact(&key, &value).into_inner();
                    let value = self.redact_nested_url_value(value, depth);
                    serializer.append_pair(&key, value.as_ref());
                }
                output.set_query(Some(&serializer.finish()));
            } else {
                output.set_query(Some(markers::INVALID_QUERY));
            }
        }
        output.to_string()
    }

    /// Redacts a complete HTTP URL embedded in a non-sensitive query value.
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
    /// * `content_type_header` - Optional parser-selection header.
    /// * `truncated` - Whether bytes are known to follow the prefix.
    ///
    /// # Returns
    ///
    /// Unescaped redacted text and its outcome status.
    #[must_use = "redacted body text and its status must be handled together"]
    fn redact_body_inner(
        &self,
        bounded: &[u8],
        content_type_header: Option<&HeaderValue>,
        truncated: bool,
    ) -> (String, BodyRedactionStatus) {
        if bounded.is_empty() {
            return (String::new(), BodyRedactionStatus::Empty);
        }
        let content_type = match content_type_header.map(HeaderValue::to_str) {
            Some(Ok(value)) => Some(value),
            Some(Err(_)) => {
                return (
                    markers::INVALID_CONTENT_TYPE.to_string(),
                    BodyRedactionStatus::Redacted(
                        BodyRedactionReason::InvalidContentType,
                    ),
                );
            }
            None => None,
        };
        if content_type.is_some_and(|value| !content_type::is_valid(value)) {
            return (
                markers::INVALID_CONTENT_TYPE.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidContentType,
                ),
            );
        }
        if content_type.is_some_and(content_type::is_multipart) {
            if truncated {
                return (
                    markers::MULTIPART_BODY.to_string(),
                    BodyRedactionStatus::Redacted(
                        BodyRedactionReason::TruncatedMultipart,
                    ),
                );
            }
            if let Some((text, passed)) = multipart::redact(
                &self.body_redactor,
                content_type.unwrap_or_default(),
                bounded,
                self.policy.text_body_policy(),
                self.policy.unkeyed_json_value_policy(),
            ) {
                return (
                    text,
                    if passed {
                        BodyRedactionStatus::PassedThrough
                    } else {
                        BodyRedactionStatus::Structured
                    },
                );
            }
            return (
                markers::MULTIPART_BODY.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidMultipart,
                ),
            );
        }
        if content_type.is_some_and(content_type::is_ndjson) {
            return self.redact_ndjson(bounded, truncated);
        }
        let trimmed = trim_ascii_whitespace(bounded);
        if content_type.is_some_and(content_type::is_json)
            || (content_type.is_none()
                && matches!(trimmed.first(), Some(b'{') | Some(b'[')))
        {
            return self.redact_json(bounded, truncated);
        }
        if content_type.is_some_and(content_type::is_form) {
            return self.redact_body_form(bounded, truncated);
        }
        self.redact_fallback(bounded, content_type)
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
    /// Redacted JSON or a fixed fail-closed marker and status.
    #[must_use = "redacted JSON text and its status must be handled together"]
    fn redact_json(
        &self,
        bounded: &[u8],
        truncated: bool,
    ) -> (String, BodyRedactionStatus) {
        if truncated {
            return (
                markers::INVALID_OR_TRUNCATED_JSON.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidOrTruncatedJson,
                ),
            );
        }
        let Ok(mut value) = serde_json::from_slice(bounded) else {
            return (
                markers::INVALID_JSON.to_string(),
                BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson),
            );
        };
        let passed = json::redact(
            &self.body_redactor,
            &mut value,
            self.policy.unkeyed_json_value_policy(),
        );
        match serde_json::to_string(&value) {
            Ok(text) => (
                text,
                if passed {
                    BodyRedactionStatus::PassedThrough
                } else {
                    BodyRedactionStatus::Structured
                },
            ),
            Err(_) => (
                markers::INVALID_JSON.to_string(),
                BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson),
            ),
        }
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
    /// Redacted NDJSON or a fixed fail-closed marker and status.
    #[must_use = "redacted NDJSON text and its status must be handled together"]
    fn redact_ndjson(
        &self,
        bounded: &[u8],
        truncated: bool,
    ) -> (String, BodyRedactionStatus) {
        if truncated {
            return (
                markers::INVALID_OR_TRUNCATED_NDJSON.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidOrTruncatedNdjson,
                ),
            );
        }
        match json::redact_ndjson(
            &self.body_redactor,
            bounded,
            self.policy.unkeyed_json_value_policy(),
        ) {
            Some((output, passed)) => (
                output,
                if passed {
                    BodyRedactionStatus::PassedThrough
                } else {
                    BodyRedactionStatus::Structured
                },
            ),
            None => (
                markers::INVALID_NDJSON.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidNdjson,
                ),
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
    /// Redacted form text or a fixed invalid marker and status.
    #[must_use = "redacted form text and its status must be handled together"]
    fn redact_body_form(
        &self,
        bounded: &[u8],
        truncated: bool,
    ) -> (String, BodyRedactionStatus) {
        if truncated {
            return (
                markers::INVALID_OR_TRUNCATED_FORM.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidOrTruncatedFormUrlEncoded,
                ),
            );
        }
        if !form::is_valid(bounded) {
            return (
                markers::INVALID_FORM.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::InvalidFormUrlEncoded,
                ),
            );
        }
        (
            form::redact(&self.body_redactor, bounded),
            BodyRedactionStatus::Structured,
        )
    }

    /// Redacts unsupported, opaque-text, or binary bounded input.
    ///
    /// # Parameters
    ///
    /// * `bounded` - Bounded fallback bytes.
    /// * `content_type_value` - Optional decoded Content-Type text.
    ///
    /// # Returns
    ///
    /// A policy-controlled text marker or binary summary and status.
    #[must_use = "fallback text and its status must be handled together"]
    fn redact_fallback(
        &self,
        bounded: &[u8],
        content_type_value: Option<&str>,
    ) -> (String, BodyRedactionStatus) {
        match std::str::from_utf8(bounded) {
            Err(_) => (
                format!("<binary {} bytes>", bounded.len()),
                BodyRedactionStatus::Binary,
            ),
            Ok(text)
                if content_type_value.is_some_and(content_type::is_text) =>
            {
                match self.policy.text_body_policy() {
                    TextBodyPolicy::Redact => (
                        markers::TEXT_BODY.to_string(),
                        BodyRedactionStatus::Redacted(
                            BodyRedactionReason::OpaqueText,
                        ),
                    ),
                    TextBodyPolicy::PassThrough => {
                        (text.to_string(), BodyRedactionStatus::PassedThrough)
                    }
                }
            }
            Ok(_) => (
                markers::UNSUPPORTED_BODY.to_string(),
                BodyRedactionStatus::Redacted(
                    BodyRedactionReason::UnsupportedMediaType,
                ),
            ),
        }
    }

    /// Escapes, bounds, and attaches exact source metadata to parser output.
    ///
    /// # Parameters
    ///
    /// * `parsed` - Unescaped redacted payload and status.
    /// * `capture` - Original checked source metadata.
    /// * `captured_len` - Number of bytes actually inspected.
    /// * `budget_truncated` - Whether the input budget omitted captured bytes.
    /// * `budget` - Hard output limit.
    ///
    /// # Returns
    ///
    /// A log-safe bounded body result with exact available metadata.
    fn finish_body_redaction(
        parsed: (String, BodyRedactionStatus),
        capture: BodyCapture<'_>,
        captured_len: usize,
        budget_truncated: bool,
        budget: BodyBudget,
    ) -> BodyRedaction {
        let (parsed_text, status) = parsed;
        let escaped = RedactedText::new(parsed_text.into())
            .escape_for_log()
            .to_string();
        let source_truncated =
            capture.is_source_truncated() || budget_truncated;
        let output_truncated = escaped.len() > budget.max_output_bytes()
            || (source_truncated
                && escaped.len() + markers::TRUNCATED.len()
                    > budget.max_output_bytes());
        let truncated = source_truncated || output_truncated;
        let text = if truncated {
            let payload_budget =
                budget.max_output_bytes() - markers::TRUNCATED.len();
            let end = utf8_prefix_len(&escaped, payload_budget);
            format!("{}{}", &escaped[..end], markers::TRUNCATED)
        } else {
            escaped
        };
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

    /// Wraps owned text after escaping all log-unsafe characters.
    ///
    /// # Parameters
    ///
    /// * `text` - Redacted but not yet escaped text.
    ///
    /// # Returns
    ///
    /// Owned text safe for plain log rendering.
    #[inline(always)]
    fn safe_owned(text: String) -> LogSafeText<'static> {
        RedactedText::new(text.into()).escape_for_log()
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

/// Finds the longest UTF-8 prefix no longer than a byte budget.
///
/// # Parameters
///
/// * `value` - Valid UTF-8 text.
/// * `budget` - Maximum prefix byte length.
///
/// # Returns
///
/// A byte offset at a valid character boundary.
#[must_use]
fn utf8_prefix_len(value: &str, budget: usize) -> usize {
    let mut end = value.len().min(budget);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    end
}
