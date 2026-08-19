// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for serde support on redacted domain views.

#[cfg(feature = "serde")]
use qubit_redact::RedactionPolicy;
#[cfg(feature = "serde")]
#[cfg(feature = "serde")]
use qubit_redact::internal::RedactSerialize;
#[cfg(feature = "serde")]
use qubit_redact::internal::RedactedSerialize;
#[cfg(feature = "serde")]
struct SerializableValue;

#[cfg(feature = "serde")]
impl RedactSerialize for SerializableValue {
    /// Serializes a stable value through the nested adapter.
    fn serialize_redacted<S>(&self, _policy: &RedactionPolicy, serializer: S) -> Result<S::Ok, S::Error>
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
    let rendered =
        serde_json::to_value(RedactedSerialize::new(&value, &policy)).expect("nested redacted value should serialize");

    assert_eq!(rendered, serde_json::json!("safe"));
}

/// The built-in nested container serializers must preserve their normal serde
/// shape while routing each contained value through `RedactSerialize`.
#[cfg(feature = "serde")]
#[test]
fn test_nested_redact_serialize_supports_option_box_and_vector_shapes() {
    let policy = RedactionPolicy::default();
    let present = Some(SerializableValue);
    let absent: Option<SerializableValue> = None;
    let boxed = Box::new(SerializableValue);
    let values = vec![SerializableValue, SerializableValue];

    let present = present.serialize_redacted(&policy, serde_json::value::Serializer);
    let absent = absent.serialize_redacted(&policy, serde_json::value::Serializer);
    let boxed = boxed.serialize_redacted(&policy, serde_json::value::Serializer);
    let values = values.serialize_redacted(&policy, serde_json::value::Serializer);

    assert_eq!(
        present.expect("present option should serialize"),
        serde_json::json!("safe")
    );
    assert_eq!(absent.expect("absent option should serialize"), serde_json::Value::Null);
    assert_eq!(boxed.expect("boxed value should serialize"), serde_json::json!("safe"));
    assert_eq!(
        values.expect("vector should serialize"),
        serde_json::json!(["safe", "safe"])
    );
}
