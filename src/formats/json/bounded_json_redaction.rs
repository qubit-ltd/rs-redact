// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! In-place conversion of JSON text to its compact redacted representation.

use serde_json::Value;
use serde_json::from_str;
use serde_json::to_writer;

use super::internal::RedactedValue;
use crate::RedactionPolicy;
use crate::Sensitivity;
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

/// Redacts JSON text while enforcing the supplied output bound.
pub(super) fn redacted_json_text_bounded(
    text: &str,
    policy: &RedactionPolicy,
    max_output: usize,
) -> BoundedJsonRedaction {
    if policy.is_disabled() {
        return BoundedJsonRedaction::Complete(text.to_owned());
    }
    #[cfg(test)]
    super::parse_counter::record_json_parse();
    if !super::is_valid_json_text(text) {
        return BoundedJsonRedaction::Invalid(opaque_secret(policy));
    }
    let Ok(value) = from_str::<Value>(text) else {
        return BoundedJsonRedaction::Invalid(opaque_secret(policy));
    };
    redacted_json_value_bounded(&value, policy, max_output)
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
    BoundedJsonRedaction::Complete(writer.into_string().unwrap_or_else(|| opaque_secret(policy)))
}

/// Returns the configured opaque replacement for invalid JSON text.
///
/// # Parameters
///
/// * policy - Immutable masking configuration.
///
/// # Returns
///
/// An owned complete replacement selected at Secret sensitivity.
fn opaque_secret(policy: &RedactionPolicy) -> String {
    policy.masking().mask_opaque(Sensitivity::Secret).to_owned()
}

#[cfg(test)]
mod tests {
    use super::BoundedJsonRedaction;
    use super::redacted_json_text_bounded;
    use crate::RedactionPolicy;

    #[test]
    fn bounded_json_text_rejects_integer_above_u64() {
        let result = redacted_json_text_bounded(r#"{"id":18446744073709551616}"#, &RedactionPolicy::standard(), 256);

        assert!(matches!(result, BoundedJsonRedaction::Invalid(_)));
    }
}
