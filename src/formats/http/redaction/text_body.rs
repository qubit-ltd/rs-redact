// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Opaque text, binary, and unsupported-body fallbacks.

use super::HttpPolicyExecutor;
use super::diagnostics;
use crate::formats::http::BodyRenderReason;
use crate::formats::http::BodyRenderStatus;
use crate::formats::http::TextBodyPolicy;
use crate::formats::http::internal::ParsedBody;
use crate::formats::http::internal::markers;

impl HttpPolicyExecutor<'_> {
    /// Redacts unsupported, opaque-text, or binary bounded input.
    #[must_use]
    pub(super) fn redact_fallback(&self, bounded: &[u8], is_text: bool, output_limit: usize) -> ParsedBody {
        match std::str::from_utf8(bounded) {
            Err(_) => ParsedBody::new(
                format!("<binary {} bytes>", bounded.len()),
                BodyRenderStatus::Binary,
                false,
            ),
            Ok(text) if is_text => match self.policy.http().text_body_policy() {
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
}
