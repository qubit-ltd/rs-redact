// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured redaction capability for JSON text values.

use std::borrow::Cow;

#[cfg(feature = "json")]
use qubit_budget::json::JsonDecodeLimits;
#[cfg(feature = "json")]
use qubit_json::decode::JsonDecoder;

use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::admit_input;
use super::redact_serialize_scope::admit_node;
use super::redact_serialize_scope::leave_node;

/// Internal structured serialization capability for JSON text fields.
#[doc(hidden)]
#[cfg(feature = "json")]
pub trait RedactJsonSerialize {
    /// Parses and serializes JSON text through structured redaction.
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}

/// Parses and redacts one JSON text value for Serde publication.
#[cfg(feature = "json")]
fn serialize_json_text<S>(serializer: S, text: &str, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let masked = || policy.masking().mask_opaque(crate::Sensitivity::Secret);
    if !admit_input(text.len()) {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    }
    if policy.is_disabled() {
        return super::redact_serialize_scope::serialize_payload(serializer, text);
    }
    if text.len() > policy.limits().max_input_bytes() {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    }
    let limits = JsonDecodeLimits::builder()
        .max_input_bytes(policy.limits().max_input_bytes())
        .value_limits(policy.limits().json_limits())
        .build();
    let Ok(value) = JsonDecoder::with_limits(limits).decode_str::<serde_json::Value>(text) else {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    };
    if !admit_structured_json_value(&value) {
        let replacement = masked();
        return super::redact_serialize_scope::serialize_payload(serializer, replacement);
    }
    let output = crate::formats::json::redact_json_value_with_limit(
        policy,
        &value,
        super::redact_serialize_scope::remaining_output_bytes(),
    );
    super::redact_serialize_scope::serialize_payload(serializer, output.text())
}

/// Admits every node and item in a parsed JSON value.
#[cfg(feature = "json")]
fn admit_structured_json_value(value: &serde_json::Value) -> bool {
    enum Admission<'value> {
        /// Enters a value and admits its node and children.
        Enter(&'value serde_json::Value),
        /// Admits one child collection item before entering its value.
        Child(&'value serde_json::Value),
        /// Leaves a value and releases its active depth slot.
        Leave,
    }

    let mut pending = vec![Admission::Enter(value)];
    let mut entered = 0_usize;
    while let Some(admission) = pending.pop() {
        match admission {
            Admission::Enter(value) => {
                if !admit_node() {
                    while entered > 0 {
                        leave_node();
                        entered -= 1;
                    }
                    return false;
                }
                entered += 1;
                pending.push(Admission::Leave);
                match value {
                    serde_json::Value::Array(values) => {
                        pending.extend(values.iter().rev().map(Admission::Child));
                    }
                    serde_json::Value::Object(entries) => {
                        pending.extend(entries.values().rev().map(Admission::Child));
                    }
                    serde_json::Value::Null
                    | serde_json::Value::Bool(_)
                    | serde_json::Value::Number(_)
                    | serde_json::Value::String(_) => {}
                }
            }
            Admission::Child(value) => {
                if !admit_collection_items(1) {
                    while entered > 0 {
                        leave_node();
                        entered -= 1;
                    }
                    return false;
                }
                pending.push(Admission::Enter(value));
            }
            Admission::Leave => {
                leave_node();
                entered -= 1;
            }
        }
    }
    true
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for String {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_json_text(serializer, self.as_str(), policy)
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for str {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_json_text(serializer, self, policy)
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for &str {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_json_text(serializer, self, policy)
    }
}

#[cfg(feature = "json")]
impl<'a> RedactJsonSerialize for Cow<'a, str> {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_json_text(serializer, self.as_ref(), policy)
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for Option<String> {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Some(value) => serialize_json_text(serializer, value, policy),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for Option<&str> {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Some(value) => serialize_json_text(serializer, value, policy),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(feature = "json")]
impl<'a> RedactJsonSerialize for Option<Cow<'a, str>> {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Some(value) => serialize_json_text(serializer, value, policy),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(all(test, feature = "json"))]
mod tests {
    use super::super::RedactedJsonSerializeRef;
    use crate::RedactionPolicy;

    /// Verifies JSON-text fields are rejected by the decoder before an
    /// over-limit tree can be materialized.
    #[test]
    fn json_text_serde_adapter_enforces_json_decode_limits() {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_json_nodes(1);
            })
            .expect("limits")
            .build()
            .expect("redaction policy");
        let source = r#"{"outer":{"token":"raw-secret"}}"#;

        let encoded = serde_json::to_value(RedactedJsonSerializeRef::new(source, &policy))
            .expect("JSON-text adapter serialization");

        assert_eq!(encoded, "<redacted>");
    }
}
