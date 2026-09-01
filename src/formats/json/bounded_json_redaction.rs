// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! In-place conversion of JSON text to its compact redacted representation.

use serde_json::Value;
use serde_json::to_writer;

use super::internal::RedactedValue;
use crate::RedactionPolicy;
use crate::runtime::OperationByteSink;

/// Bounded JSON text paired with whether budget enforcement omitted content.
pub(super) enum BoundedJsonRedaction {
    /// The complete redacted representation fit within the bound.
    Complete(
        /// Complete compact JSON text within the caller's output allowance.
        String,
    ),
    /// A non-empty safe substitute represents budget-omitted content.
    Truncated(
        /// Safe bounded fallback or prefix retained after omission.
        String,
    ),
    /// A syntactically invalid source was replaced without exposing it.
    Invalid(
        /// Opaque replacement emitted instead of invalid source text.
        String,
    ),
}

impl BoundedJsonRedaction {
    /// Consumes this result into its text and truncation provenance.
    #[must_use]
    #[inline]
    pub(super) fn into_parts(self) -> (String, bool, bool) {
        match self {
            Self::Complete(text) => (text, false, false),
            Self::Truncated(text) => (text, true, false),
            Self::Invalid(text) => (text, false, true),
        }
    }
}

/// Redacts a borrowed parsed JSON value without cloning or reparsing it.
pub(super) fn redacted_json_value_bounded(
    value: &Value,
    policy: &RedactionPolicy,
    max_output: usize,
) -> BoundedJsonRedaction {
    let mut writer = OperationByteSink::new(max_output);
    let redacted = RedactedValue::root(value, policy);
    if to_writer(&mut writer, &redacted).is_err() {
        return BoundedJsonRedaction::Truncated("<truncated>".to_owned());
    }
    BoundedJsonRedaction::Complete(
        writer
            .into_string()
            .unwrap_or_else(|| policy.masking().mask_opaque(crate::Sensitivity::Secret).to_owned()),
    )
}
