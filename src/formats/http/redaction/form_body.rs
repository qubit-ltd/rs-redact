// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URL-encoded form body rendering.

use super::HttpPolicyExecutor;
use crate::formats::http::BodyRenderReason;
use crate::formats::http::BodyRenderStatus;
use crate::formats::http::internal::ParsedBody;
use crate::formats::http::internal::form;
use crate::formats::http::internal::markers;

impl HttpPolicyExecutor<'_> {
    /// Redacts a bounded URL-encoded body.
    #[must_use]
    pub(super) fn redact_body_form(&self, bounded: &[u8], truncated: bool, output_limit: usize) -> ParsedBody {
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
}
