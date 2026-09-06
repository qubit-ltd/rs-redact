// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed JSON value serialized under one redaction policy.

use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;
use serde_json::Value;

use super::value_context::ValueContext;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Couples a borrowed JSON value with the policy and context that govern it.
pub(in crate::formats::json) struct RedactedValue<'value, 'policy> {
    /// Source value serialized without cloning or reparsing.
    value: &'value Value,
    /// Immutable policy used to resolve keys and construct masks.
    policy: &'policy RedactionPolicy,
    /// Rule context inherited from the containing JSON object, if any.
    context: ValueContext,
}

impl<'value, 'policy> RedactedValue<'value, 'policy> {
    /// Creates a root value with no enclosing field rule.
    #[must_use]
    pub(in crate::formats::json) const fn root(
        value: &'value Value,
        policy: &'policy RedactionPolicy,
    ) -> Self {
        Self {
            value,
            policy,
            context: ValueContext::Unkeyed,
        }
    }
}

impl Serialize for RedactedValue<'_, '_> {
    /// Serializes the value after applying the inherited JSON redaction rule.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.policy.is_disabled() {
            return self.value.serialize(serializer);
        }
        if let ValueContext::Keyed(level) = self.context {
            let masked = match self.value {
                Value::String(text) => self.policy.masking().mask(level, text),
                _ => std::borrow::Cow::Borrowed(self.policy.masking().mask_opaque(level)),
            };
            return serializer.serialize_str(masked.as_ref());
        }
        match self.value {
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&Self {
                        value,
                        policy: self.policy,
                        context: ValueContext::Unkeyed,
                    })?;
                }
                sequence.end()
            }
            Value::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    let context = match self.policy.resolve_field(key) {
                        crate::policy::ResolvedField::Sensitive { sensitivity } => {
                            ValueContext::Keyed(sensitivity)
                        }
                        crate::policy::ResolvedField::PassThrough => ValueContext::PassThrough,
                    };
                    map.serialize_entry(
                        key,
                        &Self {
                            value,
                            policy: self.policy,
                            context,
                        },
                    )?;
                }
                map.end()
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
                if matches!(self.context, ValueContext::Unkeyed)
                    && self.policy.unkeyed_json_value_policy()
                        == crate::UnkeyedJsonValuePolicy::Redact =>
            {
                serializer.serialize_str(
                    self.policy
                        .masking()
                        .mask_opaque(Sensitivity::Secret)
                        .as_ref(),
                )
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                self.value.serialize(serializer)
            }
        }
    }
}
