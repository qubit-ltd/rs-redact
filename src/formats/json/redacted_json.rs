// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy recursive formatting for an already parsed JSON value.

use std::fmt;

#[cfg(feature = "serde")]
use serde::Serialize;
#[cfg(feature = "serde")]
use serde::Serializer;
#[cfg(feature = "serde")]
use serde::ser::SerializeMap as _;
#[cfg(feature = "serde")]
use serde::ser::SerializeSeq as _;
use serde_json::Value;

use crate::RedactionPolicy;
use crate::domain::RedactValue as _;
use crate::domain::RedactedValue;
use crate::policy::ResolvedField;

/// A borrowed JSON value rendered with policy-aware object-key redaction.
pub struct RedactedJson<'value, 'policy> {
    /// Original parsed JSON borrowed without cloning for formatting.
    value: &'value Value,
    /// Policy used to classify every encountered object key.
    policy: &'policy RedactionPolicy,
    /// Current recursive container depth measured from the root.
    depth: usize,
    /// Whether a scalar at this node lacks an object-field key.
    unkeyed: bool,
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
    #[must_use]
    pub const fn new(value: &'value Value, policy: &'policy RedactionPolicy) -> Self {
        Self {
            value,
            policy,
            depth: 0,
            unkeyed: true,
        }
    }

    /// Creates a nested view sharing the same policy and depth budget.
    ///
    /// # Parameters
    ///
    /// * `value` - Nested JSON value borrowed from the current node.
    ///
    /// # Returns
    ///
    /// A borrowed view at the next recursive depth.
    #[inline(always)]
    #[must_use]
    fn nested<'nested>(&self, value: &'nested Value, unkeyed: bool) -> RedactedJson<'nested, 'policy> {
        RedactedJson {
            value,
            policy: self.policy,
            depth: self.depth.saturating_add(1),
            unkeyed,
        }
    }

    /// Reports whether the current container must fail closed at the depth
    /// budget.
    ///
    /// # Returns
    ///
    /// True for an object or array at or beyond the configured maximum depth.
    #[inline(always)]
    fn depth_limit_reached(&self) -> bool {
        self.depth.saturating_add(1) > self.policy.limits().json().max_depth().unwrap_or(usize::MAX)
            && matches!(self.value, Value::Object(_) | Value::Array(_))
    }

    /// Returns the policy's opaque Secret replacement for an over-depth tree.
    ///
    /// # Returns
    ///
    /// A borrowed redacted scalar safe to use in debug and Serde output.
    #[inline(always)]
    #[must_use]
    fn depth_limit_mask(&self) -> RedactedValue<'_> {
        RedactedValue::opaque(crate::Sensitivity::Secret, self.policy.masking())
    }

    /// Reports whether the current scalar must use the opaque Secret mask.
    #[inline(always)]
    #[must_use]
    fn redact_unkeyed_scalar(&self) -> bool {
        self.unkeyed
            && self.policy.unkeyed_json_value_policy() == crate::UnkeyedJsonValuePolicy::Redact
            && !matches!(self.value, Value::Array(_) | Value::Object(_))
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
        fmt_json(self, formatter)
    }
}

#[cfg(feature = "serde")]
impl Serialize for RedactedJson<'_, '_> {
    /// Serializes a bounded redacted view while retaining safe JSON shapes.
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
        S: Serializer,
    {
        if self.depth_limit_reached() {
            return Serialize::serialize(&self.depth_limit_mask(), serializer);
        }
        match self.value {
            Value::Array(values) => {
                let mut output = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    output.serialize_element(&self.nested(value, true))?;
                }
                output.end()
            }
            Value::Object(values) => {
                let mut output = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    let resolved = self.policy.resolve_field(key);
                    match resolved {
                        ResolvedField::Sensitive { sensitivity } => match value {
                            Value::String(text) => {
                                let redacted = text.redact_value(sensitivity, self.policy.masking());
                                output.serialize_entry(key, &redacted)?;
                            }
                            _ => {
                                let redacted = RedactedValue::opaque(sensitivity, self.policy.masking());
                                output.serialize_entry(key, &redacted)?;
                            }
                        },
                        ResolvedField::PassThrough => {
                            output.serialize_entry(key, &self.nested(value, false))?;
                        }
                    }
                }
                output.end()
            }
            _ if self.redact_unkeyed_scalar() => Serialize::serialize(&self.depth_limit_mask(), serializer),
            value => Serialize::serialize(value, serializer),
        }
    }
}

/// Recursively formats one JSON node with policy-aware object keys.
///
/// # Parameters
///
/// * view - Current value, policy, and recursive depth.
/// * formatter - Destination formatting context.
///
/// # Returns
///
/// The formatter result for the complete node.
///
/// # Errors
///
/// Returns a formatting error when the destination rejects output.
fn fmt_json(view: &RedactedJson<'_, '_>, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    if view.depth_limit_reached() {
        return fmt::Debug::fmt(&view.depth_limit_mask(), formatter);
    }
    match view.value {
        Value::Array(values) => {
            let mut output = formatter.debug_list();
            for value in values {
                output.entry(&view.nested(value, true));
            }
            output.finish()
        }
        Value::Object(values) => {
            let mut output = formatter.debug_map();
            for (key, value) in values {
                let resolved = view.policy.resolve_field(key);
                match resolved {
                    ResolvedField::Sensitive { sensitivity } => {
                        fmt_masked_entry(&mut output, key, value, sensitivity, view.policy.masking());
                    }
                    ResolvedField::PassThrough => {
                        output.entry(key, &view.nested(value, false));
                    }
                }
            }
            output.finish()
        }
        _ if view.redact_unkeyed_scalar() => fmt::Debug::fmt(&view.depth_limit_mask(), formatter),
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
/// * masking - Shared masking configuration selected by sensitivity.
fn fmt_masked_entry(
    output: &mut fmt::DebugMap<'_, '_>,
    key: &str,
    value: &Value,
    sensitivity: crate::Sensitivity,
    masking: &crate::MaskingPolicy,
) {
    match value {
        Value::String(text) => {
            let redacted = text.redact_value(sensitivity, masking);
            output.entry(&key, &redacted);
        }
        _ => {
            let redacted = RedactedValue::opaque(sensitivity, masking);
            output.entry(&key, &redacted);
        }
    };
}
