// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression tests for bounded domain map output and lazy child access.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;

struct Rr2Record;

impl Redact for Rr2Record {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("X", |fields| {
            fields.unredacted("a", || 1);
        });
    }
}

#[test]
fn test_rr2_record_exact_output_boundaries() {
    for maximum in [4, 7, 10, 11] {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_output_bytes(maximum);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let output = Redactor::new(policy).redact_text(&Rr2Record);
        assert!(output.text().as_str().len() <= maximum);
        assert_eq!(output.summary().usage().output_bytes(), output.text().as_str().len());
        if maximum >= 10 {
            assert_eq!(output.text().as_str(), "X { a: 1 }");
            assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
        } else {
            assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
            assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
            assert!(output.complete_text().is_err());
        }
    }
}

#[test]
fn test_rr2_structures_never_publish_incomplete_as_complete() {
    #[derive(Clone, Copy)]
    enum Shape {
        Record,
        Tuple,
        Sequence,
        Map,
        EmptyRecord,
        EmptySequence,
        EmptyMap,
        Nested,
        Transparent,
        Variant,
    }

    impl Redact for Shape {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            match self {
                Self::Record => writer.record("Record", |fields| {
                    fields.unredacted("value", || "café\n");
                }),
                Self::Tuple => writer.tuple("Tuple", |fields| {
                    fields.unredacted("value", || "café\n");
                }),
                Self::Sequence => writer.sequence(|items| {
                    items.unredacted_item(|| "café\n");
                }),
                Self::Map => writer.map(|entries| {
                    entries.unredacted_entry("value", || "café\n");
                }),
                Self::EmptyRecord => writer.record("Empty", |_| {}),
                Self::EmptySequence => writer.sequence(|_| {}),
                Self::EmptyMap => writer.map(|_| {}),
                Self::Nested => writer.record("Outer", |fields| {
                    fields.nested("child", &Rr2Record);
                }),
                Self::Transparent => writer.transparent(|fields| {
                    fields.unredacted("value", || "café\n");
                }),
                Self::Variant => writer.variant("Event", "Value", |fields| {
                    fields.unredacted("value", || "café\n");
                }),
            }
        }
    }

    for shape in [
        Shape::Record,
        Shape::Tuple,
        Shape::Sequence,
        Shape::Map,
        Shape::EmptyRecord,
        Shape::EmptySequence,
        Shape::EmptyMap,
        Shape::Nested,
        Shape::Transparent,
        Shape::Variant,
    ] {
        let baseline = Redactor::standard().redact_text(&shape);
        let complete_text = baseline.text().as_str();
        assert_eq!(baseline.summary().completion(), RedactionCompletion::Complete);

        for maximum in 0..=complete_text.len() + 3 {
            let policy = RedactionPolicy::builder()
                .limits(|limits| {
                    limits.max_output_bytes(maximum);
                })
                .expect("output limit should be valid")
                .build()
                .expect("policy should build");
            let output = Redactor::new(policy).redact_text(&shape);
            assert!(output.text().as_str().len() <= maximum);
            if output.summary().completion() == RedactionCompletion::Complete {
                assert_eq!(output.text().as_str(), complete_text);
            } else {
                assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
            }
        }
    }
}

struct DebugCalls<'counter>(&'counter Cell<usize>);

impl fmt::Debug for DebugCalls<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        formatter.write_str("debug-value")
    }
}

struct RedactCalls<'counter>(&'counter Cell<usize>);

impl Redact for RedactCalls<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        self.0.set(self.0.get() + 1);
        writer.literal("nested-value");
    }
}

#[derive(Clone, Copy)]
enum EntryKind<'counter> {
    Debug(&'counter Cell<usize>),
    Nested(&'counter Cell<usize>),
}

struct MapEntry<'counter>(EntryKind<'counter>);

impl Redact for MapEntry<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.map(|entries| match self.0 {
            EntryKind::Debug(calls) => {
                entries.unredacted_entry("long-key", || DebugCalls(calls));
            }
            EntryKind::Nested(calls) => {
                entries.nested_entry("long-key", &RedactCalls(calls));
            }
        });
    }
}

fn output_prefix_end(output: &str, needle: &str) -> usize {
    output.find(needle).expect("normal output should contain the map key") + needle.len()
}

#[test]
fn test_redaction_output_boundary_stops_map_entry_value_access() {
    for nested in [false, true] {
        let calls = Cell::new(0);
        let value = MapEntry(if nested {
            EntryKind::Nested(&calls)
        } else {
            EntryKind::Debug(&calls)
        });
        let redactor = Redactor::standard();
        let complete = redactor.redact_text(&value);
        let needle = "long-key: ";
        let prefix_end = output_prefix_end(complete.text().as_str(), needle);

        assert_eq!(calls.get(), 1, "the complete budget should reach the child");
        assert_eq!(complete.summary().completion(), RedactionCompletion::Complete);

        for maximum in 0..=prefix_end {
            calls.set(0);
            let policy = RedactionPolicy::builder()
                .limits(|limits| {
                    limits.max_output_bytes(maximum);
                })
                .expect("output limit should be valid")
                .build()
                .expect("policy should build");
            let output = Redactor::new(policy).redact_text(&value);

            assert_eq!(calls.get(), 0, "budget {maximum} must stop after the key prefix");
            assert!(output.text().as_str().len() <= maximum);
        }

        calls.set(0);
        let output = redactor.redact_text(&value);
        assert_eq!(calls.get(), 1);
        assert_eq!(output.summary().usage().output_bytes(), output.text().as_str().len());
    }
}

struct MapField {
    entries: BTreeMap<String, String>,
}

impl Redact for MapField {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("MapField", |fields| {
            fields.map("attributes", &self.entries);
            fields.unredacted("next", || 1_u8);
        });
    }
}

#[test]
fn test_disabled_map_field_keeps_separator_before_next_field() {
    for (entries, expected) in [
        (BTreeMap::new(), "MapField { attributes: {}, next: 1 }"),
        (
            BTreeMap::from([("x".to_owned(), "y".to_owned())]),
            "MapField { attributes: {\"x\": \"y\"}, next: 1 }",
        ),
    ] {
        let output = Redactor::new(RedactionPolicy::disabled()).redact_text(&MapField { entries });

        assert_eq!(output.text().as_str(), expected);
        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    }
}

#[test]
fn test_enabled_map_field_stays_within_output_boundary() {
    let entries = BTreeMap::from([("ordinary_key".to_owned(), "ordinary_value".to_owned())]);
    let value = MapField { entries };
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.low_sensitive("ordinary_key");
        })
        .expect("field policy should be valid")
        .limits(|limits| {
            limits.max_output_bytes(28);
        })
        .expect("output limit should be valid")
        .build()
        .expect("policy should build");

    let output = Redactor::new(policy).redact_text(&value);

    assert!(output.text().as_str().len() <= 28);
    assert!(!output.text().as_str().contains("ordinary_value"));
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
}
