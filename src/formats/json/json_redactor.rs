// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Immediate JSON redaction operations.

use serde_json::Value;

use super::JsonRedactionOutput;
use super::bounded_json_redaction::redacted_json_text_bounded;
use super::bounded_json_redaction::redacted_json_value_bounded;
use crate::RedactedText;
use crate::RedactionPolicy;
use crate::Sensitivity;
use crate::RedactionOutput;

/// Applies one immutable policy to JSON values or JSON text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRedactor {
    policy: RedactionPolicy,
}

impl JsonRedactor {
    /// Creates an immediate JSON redactor from a policy snapshot.
    #[must_use]
    pub const fn new(policy: RedactionPolicy) -> Self {
        Self { policy }
    }

    /// Returns the immutable policy snapshot.
    #[must_use]
    pub const fn policy(&self) -> &RedactionPolicy {
        &self.policy
    }

    /// Redacts JSON source text without creating a session.
    #[must_use]
    pub fn redact_text(&self, text: &str) -> JsonRedactionOutput {
        self.finish(redacted_json_text_bounded(
            text,
            &self.policy,
            usize::MAX,
        ))
    }

    /// Redacts an already materialized JSON value without creating a session.
    #[must_use]
    pub fn redact_value(&self, value: &Value) -> JsonRedactionOutput {
        self.finish(redacted_json_value_bounded(
            value,
            &self.policy,
            usize::MAX,
        ))
    }

    fn finish(&self, result: super::bounded_json_redaction::BoundedJsonRedaction) -> JsonRedactionOutput {
        let (text, truncated) = result.into_parts();
        let text = RedactedText::from_escaped(text);
        let output = if truncated {
            RedactionOutput::truncated(text).unwrap_or_else(RedactionOutput::empty)
        } else {
            RedactionOutput::complete(text)
        };
        JsonRedactionOutput::new(output)
    }
}
