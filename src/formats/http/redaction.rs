// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unified immutable HTTP redaction façade.
// qubit-style: allow multiple-public-types

use std::borrow::Cow;

mod body;
pub(super) mod diagnostics;
pub(super) mod headers;
pub(in crate::formats::http) mod url_rules;

use http::HeaderMap;
use http::HeaderValue;
use url::Url;

use super::BodyCapture;
use super::BodyRenderReason;
use super::BodyRenderStatus;
use super::FieldRedactor;
use super::TextBodyPolicy;
use super::UrlPathPolicy;
use super::admitted_body::AdmittedBody;
use super::internal::BoundedLogWriter;
use super::internal::ParsedBody;
use super::internal::content_type;
use super::internal::form;
use super::internal::json;
use super::internal::markers;
use super::internal::multipart;
use super::internal::nested_url;
use super::internal::nested_url::NestedUrl;
use crate::RedactionPolicy;
use crate::RedactionReason;
use crate::Sensitivity;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;

/// Borrows one immutable policy while executing HTTP redaction algorithms.
///
/// This executor is deliberately private to the HTTP implementation.  Session
/// adapters use the crate-private functions below so they never manufacture a
/// second redactor, session, or resource budget.
pub(in crate::formats::http) struct HttpPolicyExecutor<'policy> {
    /// The policy snapshot owned by the parent redaction session.
    policy: &'policy RedactionPolicy,
}

/// One completed HTTP rendering owned by the parent transaction.
///
/// This is deliberately an implementation detail rather than an HTTP result
/// type: HTTP never publishes a second output model. The parent transaction
/// commits its text and completion into its composer or batch publication.
pub(in crate::formats::http) struct HttpRendered {
    operation: RenderedOperation,
}

impl HttpRendered {
    /// Consumes this internal wrapper into the runtime operation
    /// representation.
    #[inline]
    pub(in crate::formats::http) fn into_operation(self) -> RenderedOperation {
        self.operation
    }
}

impl HttpPolicyExecutor<'_> {
    /// Borrows the header field-rule executor for the current operation.
    fn header_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(self.policy.rules(), self.policy.header_rules(), self.policy.masking())
    }

    /// Borrows the query field-rule executor for the current operation.
    fn query_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(self.policy.rules(), self.policy.query_rules(), self.policy.masking())
    }

    /// Borrows the structured-body field-rule executor for the current
    /// operation.
    fn body_field_redactor(&self) -> FieldRedactor<'_> {
        FieldRedactor::new(self.policy.rules(), self.policy.body_rules(), self.policy.masking())
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
    fn redact_url_str(&self, input: &str, output_limit: usize) -> HttpRendered {
        if self.policy.is_disabled() {
            return self.finish_diagnostic_with_limit(input.to_owned(), output_limit, None);
        }
        Url::parse(input).map_or_else(
            |_| {
                self.finish_diagnostic_with_limit(
                    markers::INVALID_URL.to_string(),
                    output_limit,
                    Some(RedactionReason::InvalidUri),
                )
            },
            |url| {
                let (text, truncated) = self.redact_url_text_at_depth(&url, 0, output_limit);
                self.finish_rendered_url(text, truncated)
            },
        )
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
    /// Redacts headers under an explicit final output ceiling.
    #[must_use]
    pub(super) fn redact_headers_with_limit(&self, headers: &HeaderMap, max_output_bytes: usize) -> HttpRendered {
        let mut writer = BoundedLogWriter::new(max_output_bytes, false);
        let values = headers::group_values(headers);
        self.write_grouped_headers(&mut writer, values);
        let (rendered, truncated) = writer.finish();
        HttpRendered {
            operation: (if truncated {
                OperationSink::truncated(rendered, RedactionReason::OutputLimitReached)
            } else {
                OperationSink::complete(rendered)
            })
            .finish(),
        }
    }

    /// Redacts a checked body while reusing any structured value built during
    /// admission.
    ///
    /// The admitted representation is consumed exactly once. Invalid content
    /// types and syntactically invalid structured bodies remain fail-closed.
    #[must_use]
    fn redact_body_with_content_type_and_admission(
        &self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
        invalid_content_type: bool,
        mut admitted: AdmittedBody,
        output_limit: usize,
    ) -> HttpRendered {
        if self.policy.is_disabled() {
            return self.finish_diagnostic_with_limit(
                String::from_utf8_lossy(capture.bytes()).into_owned(),
                output_limit,
                None,
            );
        }
        let input_len = capture.bytes().len();
        let bounded = &capture.bytes()[..input_len];
        let budget_truncated = input_len < capture.bytes().len();

        let truncated = capture.is_source_truncated() || budget_truncated;
        let parsed = if invalid_content_type {
            Self::invalid_content_type_body()
        } else {
            match &mut admitted {
                AdmittedBody::Json(value) => self.redact_json_value(bounded, value, truncated, output_limit),
                AdmittedBody::InvalidJson => Self::invalid_json_body(),
                AdmittedBody::Ndjson {
                    lines,
                    trailing_newline,
                } => self.redact_ndjson_values(lines, *trailing_newline, truncated, output_limit),
                AdmittedBody::InvalidNdjson => Self::invalid_ndjson_body(),
                AdmittedBody::Other => self.redact_body_inner(bounded, content_type, truncated, output_limit),
            }
        };
        Self::finish_body_redaction(parsed, capture, input_len, budget_truncated, output_limit)
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
    fn redact_url_text_at_depth(&self, url: &Url, depth: usize, output_limit: usize) -> (String, bool) {
        let mut writer = BoundedLogWriter::new(output_limit, false);
        let _ = writer.write_str(url.scheme());
        let _ = writer.write_str(":");

        if url.cannot_be_a_base() {
            let _ = writer.write_str(url.path());
            self.write_url_query(&mut writer, url, depth);
            self.write_url_fragment(&mut writer, url);
            return writer.finish();
        }

        let _ = writer.write_str("//");
        if !url.username().is_empty() {
            let masked = self
                .query_field_redactor()
                .mask_bounded(Sensitivity::High, url.username(), writer.remaining_bytes())
                .into_owned();
            let _ = writer.write_str(&masked);
        }
        if let Some(password) = url.password() {
            let _ = writer.write_str(":");
            let masked = self
                .query_field_redactor()
                .mask_bounded(Sensitivity::Secret, password, writer.remaining_bytes())
                .into_owned();
            let _ = writer.write_str(&masked);
        }
        if !url.username().is_empty() || url.password().is_some() {
            let _ = writer.write_str("@");
        }
        if let Some(host) = url.host_str() {
            let _ = writer.write_str(host);
        }
        if let Some(port) = url.port() {
            let _ = writer.write_str(":");
            let _ = writer.write_str(&port.to_string());
        }
        if self.policy.url_path_policy() == UrlPathPolicy::Redact && url.path() != "/" {
            let _ = writer.write_str("/<redacted>");
        } else {
            let _ = writer.write_str(url.path());
        }
        self.write_url_query(&mut writer, url, depth);
        self.write_url_fragment(&mut writer, url);
        writer.finish()
    }

    /// Writes a redacted query string without exceeding the URL output ceiling.
    fn write_url_query(&self, writer: &mut BoundedLogWriter, url: &Url, depth: usize) {
        let Some(query) = url.query() else {
            return;
        };
        let _ = writer.write_str("?");
        if !form::is_valid(query.as_bytes()) {
            let _ = writer.write_str(markers::INVALID_QUERY);
            return;
        }
        let mut redacted_query = String::new();
        for (key, value) in url.query_pairs() {
            let remaining = writer.remaining_bytes().saturating_sub(redacted_query.len());
            let value = self
                .query_field_redactor()
                .redact_bounded(&key, &value, remaining)
                .into_inner();
            let (value, nested_truncated) = self.redact_nested_url_value(value, depth, remaining);
            if !form::append_pair_bounded(&mut redacted_query, &key, value.as_ref(), remaining) {
                break;
            }
            if nested_truncated {
                writer.mark_truncated();
                break;
            }
        }
        let _ = writer.write_str(&redacted_query);
    }

    /// Writes a redacted URL fragment without exceeding the URL output ceiling.
    fn write_url_fragment(&self, writer: &mut BoundedLogWriter, url: &Url) {
        let Some(fragment) = url.fragment() else {
            return;
        };
        let _ = writer.write_str("#");
        let masked = self
            .query_field_redactor()
            .mask_bounded(Sensitivity::High, fragment, writer.remaining_bytes());
        let _ = writer.write_str(masked.as_ref());
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
    ) -> (Cow<'a, str>, bool) {
        let raw = match value {
            Cow::Borrowed(raw) => raw,
            Cow::Owned(masked) => return (Cow::Owned(masked), false),
        };
        match nested_url::detect(raw) {
            NestedUrl::NotUrl => (Cow::Borrowed(raw), false),
            NestedUrl::Parsed(url) if depth < url_rules::MAX_NESTED_URL_DEPTH => {
                let (text, truncated) = self.redact_url_text_at_depth(&url, depth + 1, output_limit);
                (Cow::Owned(text), truncated)
            }
            NestedUrl::Parsed(_) | NestedUrl::LimitExceeded => (Cow::Borrowed(markers::NESTED_URL_LIMIT), false),
            NestedUrl::Invalid => (Cow::Borrowed(markers::INVALID_URL), false),
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
            return ParsedBody::new(String::new(), BodyRenderStatus::Empty, false);
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
                    BodyRenderStatus::Redacted(BodyRenderReason::TruncatedMultipart),
                    false,
                );
            }
            if let Some(boundary) = boundary.as_deref()
                && let Some((text, passed, rendered_truncated)) = multipart::redact(
                    &self.body_field_redactor(),
                    boundary,
                    *require_form_data,
                    bounded,
                    self.policy,
                    output_limit,
                )
            {
                return ParsedBody::new(
                    text,
                    if passed {
                        BodyRenderStatus::PassedThrough
                    } else {
                        BodyRenderStatus::Structured
                    },
                    rendered_truncated,
                );
            }
            return ParsedBody::new(
                markers::MULTIPART_BODY.to_string(),
                BodyRenderStatus::Redacted(BodyRenderReason::InvalidMultipart),
                false,
            );
        }
        if matches!(&content_type, Some(content_type::ContentType::Ndjson)) {
            return if truncated {
                ParsedBody::new(
                    markers::INVALID_OR_TRUNCATED_NDJSON.to_string(),
                    BodyRenderStatus::Redacted(BodyRenderReason::InvalidOrTruncatedNdjson),
                    false,
                )
            } else {
                Self::invalid_ndjson_body()
            };
        }
        let trimmed = body::trim_ascii_whitespace(bounded);
        if matches!(&content_type, Some(content_type::ContentType::Json))
            || (content_type.is_none() && matches!(trimmed.first(), Some(b'{') | Some(b'[')))
        {
            return if truncated {
                ParsedBody::new(
                    markers::INVALID_OR_TRUNCATED_JSON.to_string(),
                    BodyRenderStatus::Redacted(BodyRenderReason::InvalidOrTruncatedJson),
                    false,
                )
            } else {
                Self::invalid_json_body()
            };
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

    /// Redacts one admitted JSON tree without parsing its source again.
    ///
    /// Source truncation and bounded array output retain the same diagnostic
    /// markers as the direct parser path.
    #[must_use]
    fn redact_json_value(
        &self,
        bounded: &[u8],
        value: &mut serde_json::Value,
        truncated: bool,
        output_limit: usize,
    ) -> ParsedBody {
        if truncated {
            return ParsedBody::new(
                markers::INVALID_OR_TRUNCATED_JSON.to_string(),
                BodyRenderStatus::Redacted(BodyRenderReason::InvalidOrTruncatedJson),
                false,
            );
        }
        if matches!(value, serde_json::Value::Array(_)) && bounded.len() > output_limit {
            return ParsedBody::new(markers::TRUNCATED.to_string(), BodyRenderStatus::Structured, true);
        }
        let passed = json::redact(
            &self.body_field_redactor(),
            value,
            self.policy.unkeyed_json_value_policy(),
        );
        match json::serialize_bounded(value, output_limit) {
            Some((text, rendered_truncated)) => ParsedBody::new(
                text,
                if passed {
                    BodyRenderStatus::PassedThrough
                } else {
                    BodyRenderStatus::Structured
                },
                rendered_truncated,
            ),
            None => ParsedBody::new(
                markers::INVALID_JSON.to_string(),
                BodyRenderStatus::Redacted(BodyRenderReason::InvalidJson),
                false,
            ),
        }
    }

    /// Creates the fail-closed result for syntactically invalid JSON.
    #[must_use]
    fn invalid_json_body() -> ParsedBody {
        ParsedBody::new(
            markers::INVALID_JSON.to_string(),
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidJson),
            false,
        )
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
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidContentType),
            false,
        )
    }

    /// Redacts admitted NDJSON values without parsing their source lines again.
    ///
    /// Empty line positions and a final newline are retained in the rendered
    /// representation before log-control escaping.
    #[must_use]
    fn redact_ndjson_values(
        &self,
        lines: &mut [Option<serde_json::Value>],
        trailing_newline: bool,
        truncated: bool,
        output_limit: usize,
    ) -> ParsedBody {
        if truncated {
            return ParsedBody::new(
                markers::INVALID_OR_TRUNCATED_NDJSON.to_string(),
                BodyRenderStatus::Redacted(BodyRenderReason::InvalidOrTruncatedNdjson),
                false,
            );
        }
        match json::redact_ndjson_values(
            &self.body_field_redactor(),
            lines,
            trailing_newline,
            self.policy.unkeyed_json_value_policy(),
            output_limit,
        ) {
            Some((output, passed, rendered_truncated)) => ParsedBody::new(
                output,
                if passed {
                    BodyRenderStatus::PassedThrough
                } else {
                    BodyRenderStatus::Structured
                },
                rendered_truncated,
            ),
            None => Self::invalid_ndjson_body(),
        }
    }

    /// Creates the fail-closed result for syntactically invalid NDJSON.
    #[must_use]
    fn invalid_ndjson_body() -> ParsedBody {
        ParsedBody::new(
            markers::INVALID_NDJSON.to_string(),
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidNdjson),
            false,
        )
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
    fn redact_body_form(&self, bounded: &[u8], truncated: bool, output_limit: usize) -> ParsedBody {
        if truncated {
            return ParsedBody::new(
                markers::INVALID_OR_TRUNCATED_FORM.to_string(),
                BodyRenderStatus::Redacted(BodyRenderReason::InvalidOrTruncatedFormUrlEncoded),
                false,
            );
        }
        if !form::is_valid(bounded) {
            return ParsedBody::new(
                markers::INVALID_FORM.to_string(),
                BodyRenderStatus::Redacted(BodyRenderReason::InvalidFormUrlEncoded),
                false,
            );
        }
        ParsedBody::new(
            form::redact_bounded(&self.body_field_redactor(), bounded, output_limit),
            BodyRenderStatus::Structured,
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
    fn redact_fallback(&self, bounded: &[u8], is_text: bool, output_limit: usize) -> ParsedBody {
        match std::str::from_utf8(bounded) {
            Err(_) => ParsedBody::new(
                format!("<binary {} bytes>", bounded.len()),
                BodyRenderStatus::Binary,
                false,
            ),
            Ok(text) if is_text => match self.policy.text_body_policy() {
                TextBodyPolicy::Redact => ParsedBody::new(
                    markers::TEXT_BODY.to_string(),
                    BodyRenderStatus::Redacted(BodyRenderReason::OpaqueText),
                    false,
                ),
                TextBodyPolicy::PassThrough => {
                    let (text, truncated) = diagnostics::bound_safe_text(text, output_limit);
                    ParsedBody::new(text, BodyRenderStatus::PassedThrough, truncated)
                }
            },
            Ok(_) => ParsedBody::new(
                markers::UNSUPPORTED_BODY.to_string(),
                BodyRenderStatus::Redacted(BodyRenderReason::UnsupportedMediaType),
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
    /// HTTP text and its completion for immediate transaction staging.
    #[must_use]
    fn finish_body_redaction(
        parsed: ParsedBody,
        capture: BodyCapture<'_>,
        captured_len: usize,
        budget_truncated: bool,
        output_limit: usize,
    ) -> HttpRendered {
        let (parsed_text, status, rendered_truncated) = parsed.into_parts();
        let source_truncated = capture.is_source_truncated() || budget_truncated || rendered_truncated;
        let mut writer = BoundedLogWriter::new(output_limit, source_truncated);
        let _ = writer.write_str(&parsed_text);
        let output_truncated = rendered_truncated || writer.is_output_truncated();
        let (text, _) = writer.finish();
        let _ = captured_len;
        let provenance = match status {
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidJson)
            | BodyRenderStatus::Redacted(BodyRenderReason::InvalidOrTruncatedJson)
            | BodyRenderStatus::Redacted(BodyRenderReason::InvalidNdjson)
            | BodyRenderStatus::Redacted(BodyRenderReason::InvalidOrTruncatedNdjson) => {
                Some(RedactionReason::InvalidJson)
            }
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidContentType) => {
                Some(RedactionReason::InvalidContentType)
            }
            BodyRenderStatus::Redacted(BodyRenderReason::UnsupportedMediaType) => {
                Some(RedactionReason::UnsupportedContentType)
            }
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidFormUrlEncoded)
            | BodyRenderStatus::Redacted(BodyRenderReason::InvalidOrTruncatedFormUrlEncoded) => {
                Some(RedactionReason::InvalidForm)
            }
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidMultipart)
            | BodyRenderStatus::Redacted(BodyRenderReason::TruncatedMultipart) => {
                Some(RedactionReason::InvalidMultipart)
            }
            _ => None,
        };
        let mut operation = if output_truncated {
            OperationSink::truncated(text, RedactionReason::OutputLimitReached)
        } else if capture.is_source_truncated() {
            OperationSink::truncated(text, RedactionReason::SourceTruncated)
        } else if budget_truncated {
            OperationSink::truncated(text, RedactionReason::InputLimitReached)
        } else {
            OperationSink::complete(text)
        };
        if capture.is_source_truncated() {
            operation = operation.with_reason(RedactionReason::SourceTruncated);
        }
        if budget_truncated {
            operation = operation.with_reason(RedactionReason::InputLimitReached);
        }
        if let Some(reason) = provenance {
            operation = operation.with_reason(reason);
        }
        HttpRendered {
            operation: operation.finish(),
        }
    }
}

/// Parses and redacts an URL string through a parent session policy snapshot.
#[must_use]
pub(crate) fn redact_url_str_with_policy(policy: &RedactionPolicy, input: &str, output_limit: usize) -> HttpRendered {
    HttpPolicyExecutor { policy }.redact_url_str(input, output_limit)
}

/// Redacts headers through a parent session's immutable policy snapshot.
#[must_use]
pub(crate) fn redact_headers_with_policy(
    policy: &RedactionPolicy,
    headers: &HeaderMap,
    output_limit: usize,
) -> HttpRendered {
    HttpPolicyExecutor { policy }.redact_headers_with_limit(headers, output_limit)
}

/// Redacts a captured body while reusing structure built by session admission.
#[must_use]
pub(super) fn redact_admitted_body_with_policy(
    policy: &RedactionPolicy,
    capture: BodyCapture<'_>,
    content_type: Option<&HeaderValue>,
    admitted: AdmittedBody,
    output_limit: usize,
) -> HttpRendered {
    let (content_type, invalid_content_type) = match content_type {
        Some(value) => match value.to_str() {
            Ok(value) => (Some(value), false),
            Err(_) => (None, true),
        },
        None => (None, false),
    };
    HttpPolicyExecutor { policy }.redact_body_with_content_type_and_admission(
        capture,
        content_type,
        invalid_content_type,
        admitted,
        output_limit,
    )
}

/// Redacts a captured body selected by text Content-Type while reusing
/// structure built by session admission.
#[must_use]
pub(super) fn redact_admitted_body_with_content_type_text_with_policy(
    policy: &RedactionPolicy,
    capture: BodyCapture<'_>,
    content_type: Option<&str>,
    admitted: AdmittedBody,
    output_limit: usize,
) -> HttpRendered {
    HttpPolicyExecutor { policy }.redact_body_with_content_type_and_admission(
        capture,
        content_type,
        false,
        admitted,
        output_limit,
    )
}
