// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy recursive formatting for an already parsed JSON value.

use std::fmt;

use serde_json::Value;

use crate::{RedactValue as _, RedactedValue, RedactionPolicy};

#[cfg(feature = "serde")]
use super::internal::{JsonRedactionState, JsonUnkeyedValuePolicy};

/// A borrowed JSON value rendered with policy-aware object-key redaction.
#[must_use = "format or serialize the redacted JSON view"]
pub struct RedactedJson<'value, 'policy> {
    /// Original parsed JSON borrowed without cloning for formatting.
    value: &'value Value,
    /// Policy used to classify every encountered object key.
    policy: &'policy RedactionPolicy,
}

impl<'value, 'policy> RedactedJson<'value, 'policy> {
    /// Creates a lazy redacted view over one parsed JSON value.
    ///
    /// # Parameters
    ///
    /// * value - Parsed JSON borrowed without cloning.
    /// * policy - Immutable policy used to classify object keys.
    ///
    /// # Returns
    ///
    /// A borrowed JSON redaction view.
    #[inline(always)]
    pub const fn new(value: &'value Value, policy: &'policy RedactionPolicy) -> Self {
        Self { value, policy }
    }

    /// Clones and redacts the value for owned output protocols.
    ///
    /// # Returns
    ///
    /// An owned JSON value with every sensitive keyed value replaced.
    #[cfg(feature = "serde")]
    fn to_redacted_value(&self) -> Value {
        let mut value = self.value.clone();
        let mut remaining_mask_bytes = usize::MAX;
        let mut state = JsonRedactionState::new(
            self.policy,
            JsonUnkeyedValuePolicy::PassThrough,
            &mut remaining_mask_bytes,
        );
        let _ = state.redact(&mut value);
        value
    }
}

impl fmt::Debug for RedactedJson<'_, '_> {
    /// Formats nested objects and arrays while masking policy-selected values.
    ///
    /// # Parameters
    ///
    /// * formatter - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result for the redacted JSON representation.
    ///
    /// # Errors
    ///
    /// Returns a formatting error when the destination rejects output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_json(self.value, self.policy, formatter)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for RedactedJson<'_, '_> {
    /// Serializes a redacted clone while retaining the JSON value shape.
    ///
    /// # Type Parameters
    ///
    /// * S - Destination serializer type.
    ///
    /// # Parameters
    ///
    /// * serializer - Destination serde serializer.
    ///
    /// # Returns
    ///
    /// The destination serializer result.
    ///
    /// # Errors
    ///
    /// Returns the destination serializer error unchanged.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&self.to_redacted_value(), serializer)
    }
}

/// Recursively formats one JSON node with policy-aware object keys.
///
/// # Parameters
///
/// * value - Current node borrowed without cloning.
/// * policy - Immutable key-classification and masking policy.
/// * formatter - Destination formatting context.
///
/// # Returns
///
/// The formatter result for the complete node.
///
/// # Errors
///
/// Returns a formatting error when the destination rejects output.
fn fmt_json(
    value: &Value,
    policy: &RedactionPolicy,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match value {
        Value::Array(values) => {
            let mut output = formatter.debug_list();
            for value in values {
                output.entry(&RedactedJson::new(value, policy));
            }
            output.finish()
        }
        Value::Object(values) => {
            let mut output = formatter.debug_map();
            for (key, value) in values {
                if let Some(sensitivity) = policy.sensitivity_for(key) {
                    fmt_masked_entry(&mut output, key, value, sensitivity, policy);
                } else {
                    output.entry(key, &RedactedJson::new(value, policy));
                }
            }
            output.finish()
        }
        value => fmt::Debug::fmt(value, formatter),
    }
}

/// Writes one object entry whose key selected a sensitivity level.
///
/// # Parameters
///
/// * output - In-progress debug map.
/// * key - Original object key preserved in output.
/// * value - Sensitive value to replace.
/// * sensitivity - Level selecting the configured mask.
/// * policy - Immutable masking configuration.
fn fmt_masked_entry(
    output: &mut fmt::DebugMap<'_, '_>,
    key: &str,
    value: &Value,
    sensitivity: crate::Sensitivity,
    policy: &RedactionPolicy,
) {
    match value {
        Value::String(text) => {
            let redacted = text.redact_value(sensitivity, policy.masking());
            output.entry(&key, &redacted);
        }
        _ => {
            let redacted = RedactedValue::opaque(sensitivity, policy.masking());
            output.entry(&key, &redacted);
        }
    };
}
