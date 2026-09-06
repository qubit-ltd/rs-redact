// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression coverage for admission of domain field and map keys.

use std::cell::Cell;
use std::collections::BTreeMap;

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// Selects independently exposed key-bearing writer paths.
#[derive(Clone, Copy, Debug)]
enum KeyPath {
    UnredactedEntry,
    SensitiveEntry,
    NestedEntry,
    Field,
    Keyed,
    KeyedValue,
    Map,
}

/// Observes whether an admitted value is evaluated.
struct KeyedInput<'a> {
    key: &'a str,
    path: KeyPath,
    accesses: &'a Cell<usize>,
}

impl Redact for KeyedInput<'_> {
    /// Presents the same raw key through each public domain adapter.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        let access = || {
            self.accesses.set(self.accesses.get() + 1);
            "visible-value"
        };
        match self.path {
            KeyPath::UnredactedEntry => writer.map(|entries| {
                entries.unredacted_entry(self.key, access);
            }),
            KeyPath::SensitiveEntry => writer.map(|entries| {
                entries.sensitive_entry(Sensitivity::Low, self.key, access);
            }),
            KeyPath::NestedEntry => writer.map(|entries| {
                entries.nested_entry(self.key, &Observed(self.accesses));
            }),
            KeyPath::Field => writer.record("Input", |fields| {
                fields.unredacted(self.key, access);
            }),
            KeyPath::Keyed => writer.record("Input", |fields| {
                fields.keyed("v", self.key, access);
            }),
            KeyPath::KeyedValue => writer.record("Input", |fields| {
                fields.keyed_value("v", self.key, "visible-value");
            }),
            KeyPath::Map => writer.record("Input", |fields| {
                fields.map("v", &BTreeMap::from([(self.key, "visible-value")]));
            }),
        };
    }
}

/// Nested traversal must not start after key rejection.
struct Observed<'a>(&'a Cell<usize>);

impl Redact for Observed<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        self.0.set(self.0.get() + 1);
        writer.literal("visible-value");
    }
}

/// Creates an enabled or disabled policy with a precise per-key byte limit.
fn redactor(maximum: usize, disabled: bool) -> Redactor {
    let mut policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_key_bytes(maximum);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let _ = policy.set_disabled(disabled);
    Redactor::new(policy)
}

/// Rejected keys never reach rendering, classification, or lazy value access.
#[test]
fn test_domain_key_limits_reject_before_value_access_in_every_mode() {
    for path in [
        KeyPath::UnredactedEntry,
        KeyPath::SensitiveEntry,
        KeyPath::NestedEntry,
        KeyPath::Field,
        KeyPath::Keyed,
        KeyPath::KeyedValue,
        KeyPath::Map,
    ] {
        for disabled in [false, true] {
            let accesses = Cell::new(0);
            let input = KeyedInput {
                key: "long_key",
                path,
                accesses: &accesses,
            };
            let redactor = redactor(1, disabled);
            let output = redactor.redact_text(&input);
            assert_eq!(
                output.summary().completion(),
                RedactionCompletion::Truncated,
                "{path:?}, disabled={disabled}"
            );
            assert!(
                output
                    .summary()
                    .reasons()
                    .contains(RedactionReason::TraversalLimitReached)
            );
            assert!(!output.text().as_str().contains("long_key"));
            assert!(!output.text().as_str().contains("visible-value"));
            assert_eq!(accesses.get(), 0);
            let error = redactor
                .inspect(&input)
                .expect_err("overlong key makes inspection inconclusive");
            assert!(error.reasons().contains(RedactionReason::TraversalLimitReached));
            assert_eq!(accesses.get(), 0);
            let mut batch = redactor.batch();
            let handle = batch.redact_value(&input);
            let output = batch.finish_for_diagnostics("incomplete");
            assert_eq!(output.text(handle).as_str(), "incomplete");
        }
    }
}

/// UTF-8 bytes are checked before canonicalization, including empty keys.
#[test]
fn test_domain_key_limits_measure_raw_utf8_bytes_at_boundary() {
    for (key, maximum, accepted) in [("é", 2, true), ("é", 1, false), ("a---b", 2, false), ("", 0, true)] {
        let accesses = Cell::new(0);
        let input = KeyedInput {
            key,
            path: KeyPath::UnredactedEntry,
            accesses: &accesses,
        };
        let output = redactor(maximum, false).redact_text(&input);
        assert_eq!(
            output.summary().completion() == RedactionCompletion::Complete,
            accepted,
            "{key:?}"
        );
        assert_eq!(accesses.get(), usize::from(accepted));
    }
}

/// Derived map and sibling-key serialization must obey the same raw-key limit.
#[cfg(all(feature = "derive", feature = "json"))]
#[test]
fn test_domain_key_limits_also_apply_to_structured_classification() {
    #[derive(Redact)]
    struct MapValue {
        #[redact(map)]
        map: BTreeMap<String, String>,
    }
    #[derive(Redact)]
    struct KeyedValue {
        #[redact(skip)]
        key: String,
        #[redact(keyed_by = key)]
        v: String,
    }
    for disabled in [false, true] {
        let redactor = redactor(4, disabled);
        let map = MapValue {
            map: BTreeMap::from([("long_key".into(), "raw-value".into())]),
        };
        let keyed = KeyedValue {
            key: "long_key".into(),
            v: "raw-value".into(),
        };
        for result in [redactor.to_json(&map), redactor.to_json(&keyed)] {
            let error = result.expect_err("key limit applies before structured classification");
            assert!(error.to_string().contains("key byte budget"));
            assert!(!error.to_string().contains("raw-value"));
        }
        let exact = MapValue {
            map: BTreeMap::from([("éé".into(), "visible".into())]),
        };
        assert!(redactor.to_json(&exact).is_ok());
    }
}
