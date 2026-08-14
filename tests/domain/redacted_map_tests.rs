// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedMap`](qubit_redact::RedactedMap).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use indexmap::IndexMap;
use qubit_redact::InputOutputLimit;
use qubit_redact::LogOutputLimit;
use qubit_redact::MaskingPolicy;
use qubit_redact::RedactValue;
use qubit_redact::RedactedMap;
use qubit_redact::RedactedMapResult;
use qubit_redact::RedactedValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// Map value used to verify alternate flags and formatter failures.
struct FormatterBehavior {
    fail: bool,
}

impl fmt::Debug for FormatterBehavior {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn redaction_input_bytes(&self) -> usize {
        1
    }

    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}
/// Verifies a redacted map keeps non-sensitive values visible.
#[test]
fn test_redacted_map_preserves_visible_value() {
    let map =
        BTreeMap::from([(String::from("label"), String::from("visible"))]);
    let rendered =
        RedactedMap::new(&map, RedactionPolicy::default()).to_string();

    assert!(rendered.contains("visible"));
}

/// Verifies map output is completed while the mutable session is available.
#[test]
fn test_redacted_map_result_is_settled_at_creation() {
    let map =
        BTreeMap::from([(String::from("label"), String::from("visible"))]);
    let redactor = Redactor::default();
    let mut session = redactor.session();
    let result = RedactedMapResult::new(&map, &mut session);

    assert_eq!(format!("{:?}", result), "{\"label\": \"visible\"}");
}

/// Verifies generic map support preserves IndexMap insertion order.
#[test]
fn test_redacted_map_supports_index_map_without_runtime_coupling() {
    let map = IndexMap::from([("password", "raw"), ("label", "visible")]);

    let rendered =
        format!("{:?}", RedactedMap::new(&map, RedactionPolicy::default()),);

    assert_eq!(
        rendered,
        r#"{"password": "<redacted>", "label": "visible"}"#,
    );
}

/// Verifies map display uses its policy output budget by default.
#[test]
fn test_redacted_map_display_uses_policy_output_limit_by_default() {
    let map = BTreeMap::from([(
        String::from("label"),
        "visible diagnostic text".repeat(4),
    )]);
    let budget =
        InputOutputLimit::new(1024, InputOutputLimit::MIN_OUTPUT_BYTES)
            .expect("the minimum bounded output should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the diagnostic budget should build a policy");

    let output = RedactedMap::new(&map, policy).to_string();

    assert!(output.len() <= budget.max_output_bytes());
    assert!(output.ends_with("<truncated>"));
}

/// Verifies eager map completion preserves alternate debug formatting.
#[test]
fn test_redacted_map_preserves_alternate_debug() {
    let map = BTreeMap::from([("label", FormatterBehavior { fail: false })]);
    let view = RedactedMap::new(&map, RedactionPolicy::default());

    assert_eq!(format!("{view:?}"), "{\"label\": compact}");
    assert!(format!("{view:#?}").contains("alternate"));
}

/// Verifies eager map completion preserves a nested formatter failure.
#[test]
fn test_redacted_map_preserves_formatter_error() {
    let map = BTreeMap::from([("label", FormatterBehavior { fail: true })]);
    let view = RedactedMap::new(&map, RedactionPolicy::default());
    let mut output = String::new();

    let result = fmt::write(&mut output, format_args!("{view:?}"));

    assert_eq!(result, Err(fmt::Error));
}

/// Value whose pre-render input charge exceeds the diagnostic budget.
struct OversizedInput<'a>(&'a AtomicUsize);

impl fmt::Debug for OversizedInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fetch_add(1, Ordering::Relaxed);
        formatter.write_str("must-not-render")
    }
}

impl RedactValue for OversizedInput<'_> {
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        self.0.fetch_add(1, Ordering::Relaxed);
        RedactedValue::opaque(level, masking)
    }

    fn redaction_input_bytes(&self) -> usize {
        1_000
    }
}

/// Verifies an oversized map item is rejected before classification or value
/// rendering inspects it.
#[test]
fn test_redacted_map_admits_complete_input_before_rendering() {
    let visits = AtomicUsize::new(0);
    let map = BTreeMap::from([("label", OversizedInput(&visits))]);
    let budget = InputOutputLimit::new(1, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the minimum diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the policy should build");

    let _ = format!("{:?}", RedactedMap::new(&map, policy));

    assert_eq!(visits.load(Ordering::Relaxed), 0);
}

/// Short map value used to isolate container truncation at a long key.
struct ShortCountingValue<'a>(&'a AtomicUsize);

impl fmt::Debug for ShortCountingValue<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fetch_add(1, Ordering::Relaxed);
        formatter.write_str("x")
    }
}

impl RedactValue for ShortCountingValue<'_> {
    fn redaction_input_bytes(&self) -> usize {
        1
    }

    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

/// Verifies a long key exhausting the map writer stops later entries.
#[test]
fn test_bounded_redacted_map_stops_after_container_writer_truncates() {
    let visits = AtomicUsize::new(0);
    let map = BTreeMap::from([
        ("a".repeat(100), ShortCountingValue(&visits)),
        ("b".to_owned(), ShortCountingValue(&visits)),
        ("c".to_owned(), ShortCountingValue(&visits)),
    ]);
    let limit = LogOutputLimit::new(14)
        .expect("the limit should be valid");

    let output = RedactedMap::new(&map, RedactionPolicy::default())
        .with_output_limit(limit)
        .to_string();

    assert!(output.ends_with("<truncated>"));
    assert_eq!(visits.load(Ordering::Relaxed), 1);
}

/// Collection whose iterator records every attempted pull.
struct NextCountingMap {
    entries: Vec<(String, PullValue)>,
    nexts: Arc<AtomicUsize>,
}

/// Short, visible value used by [`NextCountingMap`].
struct PullValue;

impl fmt::Debug for PullValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("x")
    }
}

impl RedactValue for PullValue {
    fn redaction_input_bytes(&self) -> usize {
        1
    }

    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

/// Iterator that charges its counter before returning each entry.
struct NextCountingIter<'a> {
    entries: std::slice::Iter<'a, (String, PullValue)>,
    nexts: &'a AtomicUsize,
}

impl<'a> Iterator for NextCountingIter<'a> {
    type Item = (&'a String, &'a PullValue);

    fn next(&mut self) -> Option<Self::Item> {
        self.nexts.fetch_add(1, Ordering::Relaxed);
        self.entries.next().map(|(key, value)| (key, value))
    }
}

impl<'a> IntoIterator for &'a NextCountingMap {
    type Item = (&'a String, &'a PullValue);
    type IntoIter = NextCountingIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        NextCountingIter {
            entries: self.entries.iter(),
            nexts: &self.nexts,
        }
    }
}

/// Verifies an exhausted container destination is checked before the next
/// iterator pull.
#[test]
fn test_redacted_map_checks_output_before_iterator_next() {
    let nexts = Arc::new(AtomicUsize::new(0));
    let map = NextCountingMap {
        entries: vec![
            ("a".repeat(100), PullValue),
            ("b".to_owned(), PullValue),
            ("c".to_owned(), PullValue),
        ],
        nexts: Arc::clone(&nexts),
    };
    let limit = LogOutputLimit::new(14)
        .expect("the limit should be valid");

    let output = RedactedMap::new(&map, RedactionPolicy::default())
        .with_output_limit(limit)
        .to_string();

    assert!(output.ends_with("<truncated>"));
    assert_eq!(nexts.load(Ordering::Relaxed), 1);
}
