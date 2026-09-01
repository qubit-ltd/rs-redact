// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Multipart body rendering after content-type selection.

use super::HttpPolicyExecutor;
use crate::formats::http::BodyRenderReason;
use crate::formats::http::BodyRenderStatus;
use crate::formats::http::admitted_body::AdmittedMultipart;
use crate::formats::http::internal::ParsedBody;
use crate::formats::http::internal::markers;
use crate::formats::http::internal::multipart;

impl HttpPolicyExecutor<'_> {
    /// Redacts an admitted multipart body or fails closed when framing is
    /// incomplete or invalid.
    #[must_use]
    pub(super) fn redact_multipart_body(
        &self,
        bounded: &[u8],
        boundary: Option<&str>,
        require_form_data: bool,
        truncated: bool,
        output_limit: usize,
        admitted: Option<&mut AdmittedMultipart>,
    ) -> ParsedBody {
        if truncated {
            return ParsedBody::new(
                markers::MULTIPART_BODY.to_string(),
                BodyRenderStatus::Redacted(BodyRenderReason::TruncatedMultipart),
                false,
            );
        }
        if let Some(boundary) = boundary
            && let Some((text, passed, rendered_truncated)) = multipart::redact(
                &self.body_field_redactor(),
                boundary,
                require_form_data,
                bounded,
                self.policy,
                output_limit,
                admitted,
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
        ParsedBody::new(
            markers::MULTIPART_BODY.to_string(),
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidMultipart),
            false,
        )
    }
}
