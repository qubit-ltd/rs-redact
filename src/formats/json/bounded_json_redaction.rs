// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! In-place conversion of JSON text to its compact redacted representation.

use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;
use serde_json::Value;
use serde_json::from_str;
use serde_json::to_writer;

use crate::RedactionPolicy;
use crate::Sensitivity;
use crate::runtime::OperationByteSink;

/// Bounded JSON text paired with whether budget enforcement omitted content.
pub(super) enum BoundedJsonRedaction {
    /// The complete redacted representation fit within the bound.
    Complete(String),
    /// A non-empty safe substitute represents budget-omitted content.
    Truncated(String),
    /// A syntactically invalid source was replaced without exposing it.
    Invalid(String),
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
    let redacted = RedactedValue {
        value,
        policy,
        context: ValueContext::Unkeyed,
    };
    if to_writer(&mut writer, &redacted).is_err() {
        return BoundedJsonRedaction::Truncated("<truncated>".to_owned());
    }
    BoundedJsonRedaction::Complete(writer.into_string().unwrap_or_else(|| opaque_secret(policy)))
}

#[derive(Clone, Copy)]
enum ValueContext {
    Unkeyed,
    Keyed(Sensitivity),
    PassThrough,
}

struct RedactedValue<'value, 'policy> {
    value: &'value Value,
    policy: &'policy RedactionPolicy,
    context: ValueContext,
}

impl Serialize for RedactedValue<'_, '_> {
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
                        crate::policy::ResolvedField::Sensitive { sensitivity } => ValueContext::Keyed(sensitivity),
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
                    && self.policy.unkeyed_json_value_policy() == crate::UnkeyedJsonValuePolicy::Redact =>
            {
                serializer.serialize_str(self.policy.masking().mask_opaque(Sensitivity::Secret).as_ref())
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => self.value.serialize(serializer),
        }
    }
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
