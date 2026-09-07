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
use crate::formats::http::internal::AdmittedBody;
use crate::formats::http::internal::BoundedLogWriter;
use crate::formats::http::internal::ParsedBody;
use crate::formats::http::internal::content_type;
use crate::formats::http::internal::markers;

impl HttpPolicyExecutor<'_> {
    /// Creates the fail-closed result for an invalid Content-Type.
    ///
    /// # Returns
    ///
    /// The invalid-content-type marker with its parser status.
    #[must_use]
    #[inline]
    pub(super) fn invalid_content_type_body() -> ParsedBody {
        ParsedBody::new(
            markers::INVALID_CONTENT_TYPE.to_string(),
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidContentType),
            false,
        )
    }

    /// Redacts a checked body while reusing any structured value built during
    /// admission.
    ///
    /// # Parameters
    ///
    /// - `capture`: Admitted source bytes and ingress-completeness metadata.
    /// - `content_type`: Some supplied media type, or None for missing-type
    ///   behavior.
    /// - `invalid_content_type`: Whether the original header could not be
    ///   interpreted as text.
    /// - `admitted`: Parser results reused without a second structural
    ///   admission pass.
    /// - `output_limit`: Remaining output-byte ceiling for this body.
    ///
    /// # Returns
    ///
    /// A bounded escaped operation with source and parser provenance.
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
        let bounded = capture.bytes();
        let truncated = capture.is_source_truncated();
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
        Self::finish_body_redaction(parsed, capture, output_limit)
    }

    /// Dispatches a bounded body slice to a supported parser.
    ///
    /// # Parameters
    ///
    /// - `bounded`: Admitted source bytes.
    /// - `content_type`: Some media type to parse, or None to use sniffing and
    ///   fallback rules.
    /// - `truncated`: Whether the captured source was incomplete.
    /// - `output_limit`: Remaining output-byte ceiling.
    /// - `admitted`: Some reusable multipart admission state, or None for other
    ///   formats.
    ///
    /// # Returns
    ///
    /// A parsed representation or a fail-closed format marker.
    #[must_use]
    fn redact_body_inner(
        &self,
        bounded: &[u8],
        content_type: Option<&str>,
        truncated: bool,
        output_limit: usize,
        admitted: Option<&mut crate::formats::http::internal::AdmittedMultipart>,
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

    /// Escapes, bounds, and attaches source metadata to parser output.
    ///
    /// # Parameters
    ///
    /// - `parsed`: Policy-transformed parser output and its status.
    /// - `capture`: Source completeness metadata.
    /// - `output_limit`: Final escaped byte ceiling for this body.
    ///
    /// # Returns
    ///
    /// A bounded operation preserving source truncation, parser errors, and
    /// output closure.
    #[must_use]
    fn finish_body_redaction(parsed: ParsedBody, capture: BodyCapture<'_>, output_limit: usize) -> HttpRendered {
        let (parsed_text, status, rendered_truncated) = parsed.into_parts();
        let source_truncated = capture.is_source_truncated() || rendered_truncated;
        let mut writer = BoundedLogWriter::new(output_limit, source_truncated);
        let _ = writer.write_str(&parsed_text);
        let output_truncated = rendered_truncated || writer.is_output_truncated();
        let reason = if output_truncated {
            RedactionReason::OutputLimitReached
        } else {
            RedactionReason::SourceTruncated
        };
        let mut operation = writer.finish_operation(reason);
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
        if capture.is_source_truncated() {
            operation = operation.with_reason(RedactionReason::SourceTruncated);
        }
        if let Some(reason) = provenance {
            operation = operation.with_reason(reason);
        }
        HttpRendered::new(operation)
    }
}

/// Trims ASCII whitespace without decoding the input.
///
/// # Parameters
///
/// - `bytes`: Source slice to trim without allocation or decoding.
///
/// # Returns
///
/// A subslice excluding leading and trailing ASCII whitespace.
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
