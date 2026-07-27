// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedKeyedMap`](qubit_redact::RedactedKeyedMap).

use std::{
    collections::BTreeMap,
    fmt,
};

use qubit_redact::{
    Redact,
    RedactValue,
    RedactedKeyedMap,
    RedactedValue,
    RedactionPolicy,
    Sensitivity,
};

/// Nested diagnostic value whose secret must be recursively redacted.
struct NestedValue {
    /// Secret nested value.
    secret: String,
    /// Visible descriptive text.
    label: String,
}

impl Redact for NestedValue {
    /// Formats the nested value without exposing its secret.
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter
            .debug_struct("NestedValue")
            .field(
                "secret",
                &self
                    .secret
                    .redact_value(Sensitivity::Secret, policy.masking()),
            )
            .field("label", &self.label)
            .finish()
    }
}

impl RedactValue for NestedValue {
    /// Replaces the complete nested value when its outer key is sensitive.
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &'a qubit_redact::MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

/// Creates a value containing both a nested secret and a visible field.
///
/// # Returns
///
/// A stable test value for keyed-map redaction behavior.
fn nested_value() -> NestedValue {
    NestedValue {
        secret: "nested-secret".to_owned(),
        label: "visible-label".to_owned(),
    }
}

/// Verifies a keyed map recursively redacts unclassified nested values.
#[test]
fn test_redacted_keyed_map_recursively_redacts_unclassified_values() {
    let map = BTreeMap::from([
        (String::from("profile"), nested_value()),
        (String::from("tenant_secret"), nested_value()),
    ]);
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .build()
        .expect("the keyed map policy should build");

    let output = format!("{:?}", RedactedKeyedMap::new(&map, policy));

    assert!(output.contains("visible-label"));
    assert!(!output.contains("nested-secret"));
    assert_eq!(output.matches("<redacted>").count(), 2);
}
