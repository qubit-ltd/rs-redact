// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for serde support on redacted domain views.

#[cfg(feature = "serde")]
use qubit_redact::__private::RedactSerialize;
#[cfg(feature = "serde")]
use qubit_redact::__private::RedactedSerialize;
#[cfg(feature = "serde")]
use qubit_redact::RedactedMap;
#[cfg(feature = "serde")]
use qubit_redact::RedactionPolicy;
/// Asserts at compile time that a type implements [`serde::Serialize`].
#[cfg(feature = "serde")]
fn assert_serialize<T: serde::Serialize>() {}

/// Verifies redacted map views implement serde serialization.
#[cfg(feature = "serde")]
#[test]
fn test_redacted_serialize_redacted_map_implements_serialize() {
    assert_serialize::<RedactedMap<'static, std::collections::BTreeMap<String, String>>>();
}

#[cfg(feature = "serde")]
struct SerializableValue;

#[cfg(feature = "serde")]
impl RedactSerialize for SerializableValue {
    /// Serializes a stable value through the nested adapter.
    fn serialize_redacted<S>(
        &self,
        _policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("safe")
    }
}

#[cfg(feature = "serde")]
#[test]
fn test_redacted_serialize_adapter_delegates_to_nested_value() {
    let value = SerializableValue;
    let policy = RedactionPolicy::default();
    let rendered = serde_json::to_value(RedactedSerialize::new(&value, &policy))
        .expect("nested redacted value should serialize");

    assert_eq!(rendered, serde_json::json!("safe"));
}
