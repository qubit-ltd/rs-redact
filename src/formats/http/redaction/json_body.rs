// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Admitted JSON and NDJSON body rendering.

use super::HttpPolicyExecutor;
use crate::formats::http::BodyRenderReason;
use crate::formats::http::BodyRenderStatus;
use crate::formats::http::internal::ParsedBody;
use crate::formats::http::internal::json;
use crate::formats::http::internal::markers;

impl HttpPolicyExecutor<'_> {
    /// Redacts one admitted JSON tree without parsing its source again.
    #[must_use]
    pub(super) fn redact_json_value(
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
        // Root arrays may contain unkeyed pass-through scalars. When their
        // complete source representation cannot fit, do not attempt to retain
        // a partial array whose omitted element boundary would be ambiguous.
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
            None => Self::invalid_json_body(),
        }
    }

    /// Creates the fail-closed result for syntactically invalid JSON.
    #[must_use]
    pub(super) fn invalid_json_body() -> ParsedBody {
        ParsedBody::new(
            markers::INVALID_JSON.to_string(),
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidJson),
            false,
        )
    }

    /// Redacts admitted NDJSON values without parsing their source lines again.
    #[must_use]
    pub(super) fn redact_ndjson_values(
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
    pub(super) fn invalid_ndjson_body() -> ParsedBody {
        ParsedBody::new(
            markers::INVALID_NDJSON.to_string(),
            BodyRenderStatus::Redacted(BodyRenderReason::InvalidNdjson),
            false,
        )
    }
}
