// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for explicit recursive domain-object redaction adapters.

use std::fmt;

#[cfg(feature = "serde")]
use qubit_redact::__private::RedactedSerialize;
use qubit_redact::Redact;
use qubit_redact::RedactMut;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
#[cfg(feature = "serde")]
use qubit_redact::domain::RedactSerialize;
/// Minimal nested value with a fixed safe representation.
struct NestedValue;

impl Redact for NestedValue {
    /// Writes the nested value's safe representation.
    fn fmt_redacted(
        &self,
        _session: &RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str("NestedValue { secret: <redacted> }")
    }
}

impl RedactMut for NestedValue {
    /// Keeps this display-only test value unchanged during mutation.
    fn redact_in_place_with(&mut self, _policy: &RedactionPolicy) {}
}

#[cfg(feature = "serde")]
impl RedactSerialize for NestedValue {
    /// Serializes a stable nested representation for adapter tests.
    fn serialize_redacted<S>(
        &self,
        _policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("NestedValue")
    }
}

/// Verifies an option delegates redaction to its present nested value.
#[test]
fn test_nested_option_redacts_present_value() {
    assert_eq!(
        Some(NestedValue).redacted().to_string(),
        "Some(NestedValue { secret: <redacted> })"
    );
    assert_eq!(Option::<NestedValue>::None.redacted().to_string(), "None");
}

#[test]
fn test_nested_box_and_vec_redact_with_the_same_policy() {
    let policy = RedactionPolicy::default();
    let boxed = Box::new(NestedValue);
    let values = vec![NestedValue, NestedValue];

    assert_eq!(
        format!("{:?}", boxed.redacted_with(&policy)),
        "NestedValue { secret: <redacted> }",
    );
    assert_eq!(
        format!("{:?}", values.redacted_with(&policy)),
        "[NestedValue { secret: <redacted> }, NestedValue { secret: <redacted> }]",
    );
}

#[test]
fn test_nested_mutation_delegates_through_all_containers() {
    let policy = RedactionPolicy::default();
    let mut option = Some(NestedValue);
    let mut boxed = Box::new(NestedValue);
    let mut values = vec![NestedValue, NestedValue];
    let mut absent: Option<NestedValue> = None;

    RedactMut::redact_in_place_with(&mut option, &policy);
    RedactMut::redact_in_place_with(&mut boxed, &policy);
    RedactMut::redact_in_place_with(&mut values, &policy);
    RedactMut::redact_in_place_with(&mut absent, &policy);
}

#[cfg(feature = "serde")]
#[test]
fn test_nested_serialization_delegates_through_all_containers() {
    let policy = RedactionPolicy::default();
    let value = Some(NestedValue);
    let absent: Option<NestedValue> = None;
    let boxed = Box::new(NestedValue);
    let values = vec![NestedValue, NestedValue];

    let serialized =
        serde_json::to_value(RedactedSerialize::new(&value, &policy))
            .expect("present option should serialize");
    assert_eq!(serialized, serde_json::json!("NestedValue"));
    assert_eq!(
        serde_json::to_value(RedactedSerialize::new(&absent, &policy,))
            .expect("absent option should serialize"),
        serde_json::Value::Null,
    );
    assert_eq!(
        serde_json::to_value(RedactedSerialize::new(&boxed, &policy,))
            .expect("boxed value should serialize"),
        serde_json::json!("NestedValue"),
    );
    assert_eq!(
        serde_json::to_value(RedactedSerialize::new(&values, &policy,))
            .expect("sequence should serialize"),
        serde_json::json!(["NestedValue", "NestedValue"]),
    );
}
