// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured redaction capability for JSON text values.

use std::borrow::Cow;

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
        return serializer.serialize_str(replacement.as_ref());
    }
    if policy.is_disabled() {
        return serializer.serialize_str(text);
    }
    if text.len() > policy.limits().max_input_bytes() {
        let replacement = masked();
        return serializer.serialize_str(replacement.as_ref());
    }
    if !crate::formats::json::is_valid_json_text(text) {
        let replacement = masked();
        return serializer.serialize_str(replacement.as_ref());
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        let replacement = masked();
        return serializer.serialize_str(replacement.as_ref());
    };
    if !admit_structured_json_value(&value) {
        let replacement = masked();
        return serializer.serialize_str(replacement.as_ref());
    }
    let output = crate::formats::json::redact_json_value_with_limit(policy, &value, usize::MAX);
    serializer.serialize_str(output.text())
}

/// Admits every node and item in a parsed JSON value.
#[cfg(feature = "json")]
fn admit_structured_json_value(value: &serde_json::Value) -> bool {
    if !admit_node() {
        return false;
    }
    let admitted = match value {
        serde_json::Value::Array(values) => values
            .iter()
            .all(|value| admit_collection_items(1) && admit_structured_json_value(value)),
        serde_json::Value::Object(entries) => entries
            .values()
            .all(|value| admit_collection_items(1) && admit_structured_json_value(value)),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => true,
    };
    leave_node();
    admitted
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
