// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedKeyedMap`](qubit_redact::domain::RedactedKeyedMap).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use qubit_redact::InputOutputLimit;
use qubit_redact::LogOutputLimit;
use qubit_redact::MaskingPolicy;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::domain::Redact;
use qubit_redact::domain::RedactValue;
use qubit_redact::domain::RedactedKeyedMap;
use qubit_redact::domain::RedactedKeyedMapResult;
use qubit_redact::domain::RedactedValue;
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
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter
            .debug_struct("NestedValue")
            .field(
                "secret",
                &self.secret.redact_value(
                    Sensitivity::Secret,
                    _session.policy().masking(),
                ),
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("tenant_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the keyed map policy should build");

    let output = format!("{:?}", RedactedKeyedMap::new(&map, policy));

    assert!(output.contains("visible-label"));
    assert!(!output.contains("nested-secret"));
    assert_eq!(output.matches("<redacted>").count(), 2);
}

/// Verifies keyed-map output is completed while the mutable session is
/// available and retains no session-bound formatter state.
#[test]
fn test_redacted_keyed_map_result_is_settled_at_creation() {
    let map = BTreeMap::from([(
        "label".to_owned(),
        FormatterBehavior { fail: false },
    )]);
    let redactor = Redactor::default();
    let mut session = redactor.session();
    let result = RedactedKeyedMapResult::new(&map, &mut session);

    assert_eq!(format!("{:?}", result), "{\"label\": compact}");
}

/// Verifies keyed map displays escape log controls and both bounded adapters
/// honor their configured output limits.
#[test]
fn test_redacted_keyed_map_display_and_bounded_adapters() {
    let map = BTreeMap::from([(String::from("profile"), nested_value())]);
    let output_limit = InputOutputLimit::MIN_OUTPUT_BYTES;
    let budget = InputOutputLimit::builder()
        .max_input_bytes(1024)
        .max_output_bytes(output_limit)
        .build()
        .expect("the test diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the keyed map policy should build");

    let display = RedactedKeyedMap::new(&map, policy.clone()).to_string();
    let bounded = RedactedKeyedMap::new(&map, policy.clone())
        .with_output_limit(
            LogOutputLimit::builder()
                .max_bytes(output_limit)
                .build()
                .expect("the minimum output limit should be valid"),
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

/// Keyed-map value that records recursive formatter visits.
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

impl RedactValue for CountingValue<'_> {
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

/// Verifies a local output ceiling stops visiting later keyed-map values.
#[test]
fn test_bounded_keyed_map_stops_after_truncated_value() {
    let visits = AtomicUsize::new(0);
    let map = BTreeMap::from([
        ("a".to_owned(), CountingValue(&visits)),
        ("b".to_owned(), CountingValue(&visits)),
        ("c".to_owned(), CountingValue(&visits)),
    ]);
    let limit = LogOutputLimit::builder()
        .max_bytes(14)
        .build()
        .expect("the limit should be valid");

    let output = RedactedKeyedMap::new(&map, RedactionPolicy::default())
        .with_output_limit(limit)
        .to_string();

    assert!(output.ends_with("<truncated>"));
    assert_eq!(visits.load(Ordering::Relaxed), 1);
}

/// Keyed value used to verify alternate flags and formatter failures.
struct FormatterBehavior {
    fail: bool,
}

impl Redact for FormatterBehavior {
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        if self.fail {
            return Err(fmt::Error);
        }
        formatter.write_str(if formatter.alternate() {
            "alternate"
        } else {
            "compact"
        })
    }
}

impl RedactValue for FormatterBehavior {
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

/// Verifies eager keyed-map completion preserves alternate debug formatting.
#[test]
fn test_redacted_keyed_map_preserves_alternate_debug() {
    let map = BTreeMap::from([(
        "label".to_owned(),
        FormatterBehavior { fail: false },
    )]);
    let compact = format!(
        "{:?}",
        RedactedKeyedMap::new(&map, RedactionPolicy::default())
    );
    let alternate = format!(
        "{:#?}",
        RedactedKeyedMap::new(&map, RedactionPolicy::default())
    );

    assert!(compact.contains("compact"));
    assert!(alternate.contains("alternate"));
}

/// Verifies eager keyed-map completion preserves a nested formatter failure.
#[test]
fn test_redacted_keyed_map_preserves_formatter_error() {
    let map = BTreeMap::from([(
        "label".to_owned(),
        FormatterBehavior { fail: true },
    )]);
    let view = RedactedKeyedMap::new(&map, RedactionPolicy::default());
    let mut output = String::new();

    let result = fmt::write(&mut output, format_args!("{view:?}"));

    assert_eq!(result, Err(fmt::Error));
}

/// Short value used to isolate container-writer truncation at a long key.
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

impl RedactValue for ShortCountingValue<'_> {
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

/// Verifies truncation while writing a key prevents pulling and formatting
/// later map entries.
#[test]
fn test_bounded_keyed_map_stops_after_container_writer_truncates() {
    let visits = AtomicUsize::new(0);
    let map = BTreeMap::from([
        ("a".repeat(100), ShortCountingValue(&visits)),
        ("b".to_owned(), ShortCountingValue(&visits)),
        ("c".to_owned(), ShortCountingValue(&visits)),
    ]);
    let limit = LogOutputLimit::builder()
        .max_bytes(14)
        .build()
        .expect("the limit should be valid");

    let output = RedactedKeyedMap::new(&map, RedactionPolicy::default())
        .with_output_limit(limit)
        .to_string();

    assert!(output.ends_with("<truncated>"));
    assert_eq!(visits.load(Ordering::Relaxed), 1);
}
