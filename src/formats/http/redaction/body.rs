// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Body admission, parser dispatch, and publication helpers.

use super::HttpPolicyExecutor;
use super::HttpRendered;
use crate::RedactionReason;
use crate::formats::http::BodyCapture;
use crate::formats::http::BodyRenderReason;
use crate::formats::http::BodyRenderStatus;
use crate::formats::http::admitted_body::AdmittedBody;
use crate::formats::http::internal::BoundedLogWriter;
use crate::formats::http::internal::ParsedBody;
use crate::formats::http::internal::content_type;
use crate::formats::http::internal::markers;
use crate::runtime::OperationSink;

impl HttpPolicyExecutor<'_> {
    /// Redacts a checked body while reusing any structured value built during
    /// admission.
    #[must_use]
    pub(super) fn redact_body_with_content_type_and_admission(
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
                AdmittedBody::Multipart(parts) => {
                    self.redact_body_inner(bounded, content_type, truncated, output_limit, Some(parts))
                }
                AdmittedBody::Other => self.redact_body_inner(bounded, content_type, truncated, output_limit, None),
            }
        };
        Self::finish_body_redaction(parsed, capture, input_len, budget_truncated, output_limit)
    }

    /// Dispatches a bounded body slice to a supported parser.
    #[must_use]
    fn redact_body_inner(
        &self,
        bounded: &[u8],
        content_type: Option<&str>,
        truncated: bool,
        output_limit: usize,
        admitted: Option<&mut crate::formats::http::admitted_body::AdmittedMultipart>,
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
            return self.redact_multipart_body(
                bounded,
                boundary.as_deref(),
                *require_form_data,
                truncated,
                output_limit,
                admitted,
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
        let trimmed = trim_ascii_whitespace(bounded);
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

    /// Creates the fail-closed result for an invalid Content-Type.
    #[must_use]
    pub(super) fn invalid_content_type_body() -> ParsedBody {
        ParsedBody::new(
            markers::INVALID_CONTENT_TYPE.to_string(),
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidContentType),
            false,
        )
    }

    /// Escapes, bounds, and attaches source metadata to parser output.
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

/// Trims ASCII whitespace without decoding the input.
#[must_use]
pub(super) fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
