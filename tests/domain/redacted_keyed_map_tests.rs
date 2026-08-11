// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedKeyedMap`](qubit_redact::RedactedKeyedMap).

use std::collections::BTreeMap;
use std::fmt;

use qubit_redact::InputOutputLimit;
use qubit_redact::LogOutputLimit;
use qubit_redact::MaskingPolicy;
use qubit_redact::Redact;
use qubit_redact::RedactValue;
use qubit_redact::RedactedKeyedMap;
use qubit_redact::RedactedValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
use qubit_redact::Sensitivity;
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
        _session: &RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter
            .debug_struct("NestedValue")
            .field(
                "secret",
                &self
                    .secret
                    .redact_value(Sensitivity::Secret, _session.policy().masking()),
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
        masking: &MaskingPolicy,
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
        .expect("the test builder input should be valid")
        .build()
        .expect("the keyed map policy should build");

    let output = format!("{:?}", RedactedKeyedMap::new(&map, policy));

    assert!(output.contains("visible-label"));
    assert!(!output.contains("nested-secret"));
    assert_eq!(output.matches("<redacted>").count(), 2);
}

/// Verifies keyed map displays escape log controls and both bounded adapters
/// honor their configured output limits.
#[test]
fn test_redacted_keyed_map_display_and_bounded_adapters() {
    let map = BTreeMap::from([(String::from("profile"), nested_value())]);
    let output_limit = InputOutputLimit::MIN_OUTPUT_BYTES;
    let budget = InputOutputLimit::new(1024, output_limit)
        .expect("the test diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the keyed map policy should build");

    let display = RedactedKeyedMap::new(&map, policy.clone()).to_string();
    let bounded = RedactedKeyedMap::new(&map, policy.clone())
        .with_output_limit(
            LogOutputLimit::new(output_limit).expect("the minimum output limit should be valid"),
        )
        .to_string();
    let policy_bounded = RedactedKeyedMap::new(&map, policy)
        .with_policy_output_limit()
        .to_string();

    assert!(display.len() <= output_limit);
    assert!(display.ends_with("<truncated>"));
    assert!(bounded.len() <= output_limit);
    assert!(bounded.ends_with("<truncated>"));
    assert!(policy_bounded.len() <= output_limit);
    assert!(policy_bounded.ends_with("<truncated>"));
}
