// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for explicit recursive domain-object redaction adapters.

use std::fmt;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

#[cfg(feature = "serde")]
use qubit_redact::__private::RedactedSerialize;
use qubit_redact::InputOutputLimit;
use qubit_redact::LogOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
use qubit_redact::domain::Redact;
use qubit_redact::domain::RedactMut;
#[cfg(feature = "serde")]
use qubit_redact::domain::RedactSerialize;
/// Minimal nested value with a fixed safe representation.
struct NestedValue;

impl Redact for NestedValue {
    /// Writes the nested value's safe representation.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
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

/// Item that records whether bounded list formatting visits it.
struct CountingValue<'a>(&'a AtomicUsize);

impl Redact for CountingValue<'_> {
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        self.0.fetch_add(1, Ordering::Relaxed);
        formatter.write_str("你你你你你")
    }
}

/// Verifies a local output ceiling stops visiting later vector items.
#[test]
fn test_bounded_vec_stops_after_truncated_item() {
    let visits = AtomicUsize::new(0);
    let values: Vec<_> = (0..100).map(|_| CountingValue(&visits)).collect();
    let limit = LogOutputLimit::new(14).expect("the limit should be valid");

    let output = values.redacted().with_output_limit(limit).to_string();

    assert!(output.ends_with("<truncated>"));
    assert_eq!(visits.load(Ordering::Relaxed), 1);
}

/// Short item used to isolate list delimiter exhaustion.
struct ShortCountingValue<'a>(&'a AtomicUsize);

impl Redact for ShortCountingValue<'_> {
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        self.0.fetch_add(1, Ordering::Relaxed);
        formatter.write_str("x")
    }
}

/// Verifies list separators exhausting the destination stop later items.
#[test]
fn test_bounded_vec_stops_after_container_writer_truncates() {
    let visits = AtomicUsize::new(0);
    let values: Vec<_> =
        (0..100).map(|_| ShortCountingValue(&visits)).collect();
    let limit = LogOutputLimit::new(14).expect("the limit should be valid");

    let output = values.redacted().with_output_limit(limit).to_string();

    assert!(output.ends_with("<truncated>"));
    assert!(visits.load(Ordering::Relaxed) < values.len());
}

/// Item that records whether domain vector formatting visits it.
struct OversizedInput<'a>(&'a AtomicUsize);

impl Redact for OversizedInput<'_> {
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        self.0.fetch_add(1, Ordering::Relaxed);
        formatter.write_str("must-not-render")
    }
}

/// Verifies vector items render without consuming diagnostic input.
#[test]
fn test_vec_does_not_charge_item_input_before_rendering() {
    let visits = AtomicUsize::new(0);
    let values = vec![OversizedInput(&visits)];
    let input_bytes = std::mem::size_of_val(&values).saturating_add(1);
    let budget =
        InputOutputLimit::new(input_bytes, InputOutputLimit::MIN_OUTPUT_BYTES)
            .expect("the diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the policy should build");

    let output = format!("{:?}", values.redacted_with(&policy));

    assert_eq!(output, "[must-not-render]");
    assert_eq!(visits.load(Ordering::Relaxed), 1);
}

/// Child whose exact input size is aggregated by its parent option.
struct ExactInputChild<'a>(&'a AtomicUsize);

impl Redact for ExactInputChild<'_> {
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        self.0.fetch_add(1, Ordering::Relaxed);
        formatter.write_str("child")
    }
}

/// Verifies an option's pre-reserved child input is not charged again by the
/// nested output fragment.
#[test]
fn test_option_does_not_double_charge_child_input() {
    let calls = AtomicUsize::new(0);
    let value = Some(ExactInputChild(&calls));
    let budget = InputOutputLimit::new(6, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the exact aggregate input budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the policy should build");

    let output = format!("{:?}", value.redacted_with(&policy));

    assert_eq!(output, "Some(child)");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
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
