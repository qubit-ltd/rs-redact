// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression tests for explicit levels, collection admission, and disabled
//! writers.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;

#[cfg(feature = "derive")]
use qubit_redact::MaskPolicy;
use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// A counted key detects work performed before collection admission.
#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct CountedKey<'counter> {
    index: usize,
    calls: &'counter Cell<usize>,
}

impl fmt::Debug for CountedKey<'_> {
    /// Counts formatting independently of the final output text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.calls.set(self.calls.get() + 1);
        write!(formatter, "key{}", self.index)
    }
}

struct ClassifiedMap<'counter>(BTreeMap<CountedKey<'counter>, String>);

impl Redact for ClassifiedMap<'_> {
    /// Exercises the level capability used by derive on map fields.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("ClassifiedMap", |fields| {
            fields.sensitive_value(Sensitivity::Secret, "values", &self.0);
        });
    }
}

/// Ensures rejected map keys are never formatted, even under disabled policy.
#[test]
fn test_level_map_does_not_format_keys_after_collection_limit() {
    for base in [RedactionPolicy::standard(), RedactionPolicy::disabled()] {
        let calls = Cell::new(0);
        let value = ClassifiedMap(
            (0..100)
                .map(|index| (CountedKey { index, calls: &calls }, "secret".to_owned()))
                .collect(),
        );
        let policy = base
            .to_builder()
            .limits(|limits| {
                limits.max_collection_items(1);
            })
            .expect("collection limit")
            .build()
            .expect("policy");

        let output = Redactor::new(policy).redact(&value);

        assert_eq!(calls.get(), 1, "only the admitted key may be formatted");
        assert_eq!(output.summary().usage().visited_collection_items(), 1);
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    }
}

struct SensitiveCollections;

impl Redact for SensitiveCollections {
    /// Writes both collection kinds with lazy sensitive accessors.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.sequence(|items| {
            items.sensitive_item(Sensitivity::Secret, || "sequence-secret");
        });
        writer.map(|entries| {
            entries.sensitive_entry(Sensitivity::Secret, "password", || "map-secret");
        });
    }
}

/// Disabled policy restores values in sequence and map writers.
#[test]
fn test_disabled_collection_writers_restore_values() {
    let output = Redactor::new(RedactionPolicy::disabled()).redact(&SensitiveCollections);
    assert_eq!(
        output.text().as_str(),
        "[\"sequence-secret\"]{ password: \"map-secret\" }"
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Disabled inspection does not report protection that is not being applied.
#[test]
fn test_disabled_collection_inspection_has_no_sensitivity() {
    let inspection = Redactor::new(RedactionPolicy::disabled())
        .inspect(&SensitiveCollections)
        .expect("complete inspection");
    assert_eq!(inspection.max_sensitivity(), None);
}

#[cfg(feature = "derive")]
#[derive(Redact)]
struct ExplicitLevel {
    #[redact(level = "low")]
    password: String,
}

/// Explicit derive levels override both strict unknowns and the built-in floor.
#[cfg(feature = "derive")]
#[test]
fn test_explicit_derive_level_is_final_for_text_and_inspection() {
    let policy = RedactionPolicy::strict()
        .to_builder()
        .fields(|fields| {
            fields.mask(Sensitivity::Low, MaskPolicy::fixed("LOW"));
        })
        .expect("low mask")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);
    let value = ExplicitLevel {
        password: "secret".to_owned(),
    };
    let output = redactor.redact(&value);
    assert_eq!(output.text().as_str(), "ExplicitLevel { password: \"LOW\" }");
    assert_eq!(
        redactor.inspect(&value).expect("inspection").max_sensitivity(),
        Some(Sensitivity::Low)
    );
}

/// The iterator driver checks budget before pulling a rejected suffix.
#[test]
fn test_collection_drivers_stop_before_advancing_unadmitted_items() {
    struct Driven<'counter>(&'counter Cell<usize>, bool);
    impl Redact for Driven<'_> {
        /// Counts input pulls separately from value access and output
        /// accounting.
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            let values = (0..100).inspect(|_| self.0.set(self.0.get() + 1));
            if self.1 {
                writer.map(|entries| {
                    entries.for_each(values, |entries, value| {
                        entries.unredacted_entry("entry", || value);
                    });
                });
            } else {
                writer.sequence(|items| {
                    items.for_each(values, |items, value| {
                        items.unredacted_item(|| value);
                    });
                });
            }
        }
    }
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limits")
        .build()
        .expect("policy");
    for is_map in [false, true] {
        let pulls = Cell::new(0);
        let output = Redactor::new(policy.clone()).redact(&Driven(&pulls, is_map));
        assert_eq!(pulls.get(), 1);
        assert_eq!(output.summary().usage().visited_collection_items(), 1);
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    }
}

/// Exact length does not create a spurious truncation or charge an item twice.
#[test]
fn test_collection_driver_exact_budget_remains_complete() {
    struct Exact;
    impl Redact for Exact {
        /// Emits exactly one admitted item followed by one admitted entry.
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.sequence(|items| {
                items.for_each([7_u8], |items, value| {
                    items.unredacted_item(|| value);
                });
            });
            writer.map(|entries| {
                entries.for_each([8_u8], |entries, value| {
                    entries.unredacted_entry("a", || value);
                });
            });
        }
    }
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact(&Exact);
    assert_eq!(output.text().as_str(), "[7]{ a: 8 }");
    assert_eq!(output.summary().usage().visited_collection_items(), 2);
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Large debug keys stream through the bounded writer instead of a temporary
/// String.
#[test]
fn test_level_map_bounds_key_formatting_work() {
    #[derive(Eq, PartialEq, Ord, PartialOrd)]
    struct LongKey<'counter>(&'counter Cell<usize>);
    impl fmt::Debug for LongKey<'_> {
        /// Produces separately counted chunks and stops when the writer rejects
        /// one.
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            for _ in 0..1000 {
                self.0.set(self.0.get() + 1);
                formatter.write_str("0123456789")?;
            }
            Ok(())
        }
    }
    struct LargeKeyMap<'counter>(BTreeMap<LongKey<'counter>, String>);
    impl Redact for LargeKeyMap<'_> {
        /// Sends the map through the same capability as an explicitly leveled
        /// derive.
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("M", |fields| {
                fields.sensitive_value(Sensitivity::Secret, "v", &self.0);
            });
        }
    }
    let chunks = Cell::new(0);
    let value = LargeKeyMap(BTreeMap::from([(LongKey(&chunks), "secret".to_owned())]));
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(32);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact(&value);
    assert!(chunks.get() < 4, "key formatting must stop at the output limit");
    assert!(output.text().as_str().len() <= 32);
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Dynamic keys preserve laziness for both inspection and opaque masks.
#[test]
fn test_keyed_debug_accessor_is_lazy_and_uses_business_key() {
    struct Pair<'counter>(&'counter Cell<usize>);
    impl Redact for Pair<'_> {
        /// The displayed field is public, but its business key is sensitive.
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("Pair", |fields| {
                fields.keyed("public", "password", || {
                    self.0.set(self.0.get() + 1);
                    "secret"
                });
            });
        }
    }
    let calls = Cell::new(0);
    let pair = Pair(&calls);
    let redactor = Redactor::standard();
    assert_eq!(
        redactor.inspect(&pair).expect("inspection").max_sensitivity(),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        redactor.redact(&pair).text().as_str(),
        "Pair { public: \"<redacted>\" }"
    );
    assert_eq!(calls.get(), 0);
    assert!(
        Redactor::new(RedactionPolicy::disabled())
            .redact(&pair)
            .text()
            .as_str()
            .contains("secret")
    );
    assert_eq!(calls.get(), 1);
}
