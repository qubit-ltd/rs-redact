// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the [`Redact`](qubit_redact::Redact) domain contract.

use std::collections::BTreeMap;

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
/// Minimal domain value used to verify the completed transaction contract.
struct TestDomainValue;

impl Redact for TestDomainValue {
    /// Writes a fixed redacted representation without consulting source data.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("TestDomainValue { secret: <redacted> }");
    }
}

/// Verifies that the trait creates final transaction output.
#[test]
fn test_redact_redacted_returns_completed_output() {
    let output = Redactor::standard().redact(&TestDomainValue);

    assert_eq!(output.text().as_str(), "TestDomainValue { secret: <redacted> }");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Exercises the writer's record, tuple, sequence, unit, trusted, and opaque
/// sensitive-field helpers through the supported domain contract.
#[test]
fn test_redaction_writer_structured_helper_shapes_and_opaque_access() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    struct Structured<'a>(&'a AtomicUsize);

    struct Numbers;

    impl Redact for Numbers {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.sequence(|items| {
                items.unredacted_item(|| 1_u8).unredacted_item(|| 2_u8);
            });
        }
    }

    impl Redact for Structured<'_> {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("Structured", |fields| {
                fields.unredacted("unit", || "Unit");
                fields.sensitive(Sensitivity::High, "secret", || {
                    self.0.fetch_add(1, Ordering::SeqCst);
                    "must not be read"
                });
                fields.nested("pair", &Pair);
                fields.nested("numbers", &Numbers);
            });
        }
    }

    struct Pair;

    impl Redact for Pair {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.tuple("Pair", |fields| {
                fields.unredacted("", || 1_u8);
                fields.unredacted("", || 2_u8);
            });
        }
    }

    let accesses = AtomicUsize::new(0);
    let output = Redactor::standard().redact(&Structured(&accesses));

    assert_eq!(accesses.load(Ordering::SeqCst), 0);
    assert_eq!(
        output.text().as_str(),
        "Structured { unit: \"Unit\", secret: \"<redacted>\", pair: Pair(1, 2), numbers: [1, 2] }"
    );
}

/// Verifies item-only and entry-only scopes preserve masking and accessor
/// short-circuit semantics after their capabilities are split.
#[test]
fn test_redaction_writer_sequence_and_map_scopes_enforce_their_contracts() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    struct SequenceValue<'access>(&'access AtomicUsize);

    impl Redact for SequenceValue<'_> {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.sequence(|items| {
                items
                    .unredacted_item(|| "visible")
                    .sensitive_item(Sensitivity::Secret, || {
                        self.0.fetch_add(1, Ordering::SeqCst);
                        "must not be read"
                    });
            });
        }
    }

    struct MapValue<'access>(&'access AtomicUsize);

    impl Redact for MapValue<'_> {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.map(|entries| {
                entries
                    .unredacted_entry("public", || "visible")
                    .sensitive_entry(Sensitivity::Secret, "secret", || {
                        self.0.fetch_add(1, Ordering::SeqCst);
                        "must not be read"
                    })
                    .nested_entry("nested", &TestDomainValue);
            });
        }
    }

    let accesses = AtomicUsize::new(0);
    let sequence = Redactor::standard().redact(&SequenceValue(&accesses));
    let map = Redactor::standard().redact(&MapValue(&accesses));

    assert_eq!(accesses.load(Ordering::SeqCst), 0);
    assert_eq!(sequence.text().as_str(), r#"["visible", "<redacted>"]"#);
    assert_eq!(
        map.text().as_str(),
        r#"{ public: "visible", secret: "<redacted>", nested: TestDomainValue { secret: <redacted> } }"#
    );
}

/// Verifies a domain map classifies each dynamic key through the active policy.
#[test]
fn test_redaction_fields_map_classifies_each_dynamic_key() {
    struct DynamicMapValue {
        attributes: BTreeMap<String, String>,
    }

    impl Redact for DynamicMapValue {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("DynamicMapValue", |fields| {
                fields.map("attributes", self.attributes.iter());
            });
        }
    }

    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("password");
        })
        .expect("field policy should build")
        .build()
        .expect("policy should build");
    let value = DynamicMapValue {
        attributes: BTreeMap::from([
            ("password".to_owned(), "raw-secret".to_owned()),
            ("region".to_owned(), "eu-west".to_owned()),
        ]),
    };

    let output = Redactor::new(policy).redact(&value);

    assert!(!output.text().as_str().contains("raw-secret"));
    assert!(output.text().as_str().contains("<redacted>"));
    assert!(output.text().as_str().contains("eu-west"));
}

/// Verifies level mode preserves recursive container shape and masks each
/// scalar leaf independently.
#[test]
fn test_redaction_fields_sensitive_value_masks_recursive_leaves() {
    struct RecursiveLevelValue {
        values: Option<Vec<(u32, String)>>,
    }

    impl Redact for RecursiveLevelValue {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("RecursiveLevelValue", |fields| {
                fields.sensitive_value(Sensitivity::Secret, "values", &self.values);
            });
        }
    }

    let value = RecursiveLevelValue {
        values: Some(vec![(42, "raw-secret".to_owned())]),
    };

    let enabled = Redactor::standard().redact(&value);
    assert_eq!(
        enabled.text().as_str(),
        "RecursiveLevelValue { values: Some([(\"<redacted>\", \"<redacted>\")]) }"
    );
    assert!(!enabled.text().as_str().contains("42"));
    assert!(!enabled.text().as_str().contains("raw-secret"));

    let disabled = Redactor::new(RedactionPolicy::disabled()).redact(&value);
    assert_eq!(
        disabled.text().as_str(),
        "RecursiveLevelValue { values: Some([(42, \"raw-secret\")]) }"
    );
}

/// Verifies the optional decimal scalar capability is consistent between the
/// domain writer and structured Serde paths used by downstream models.
#[cfg(feature = "serde")]
#[test]
fn test_redaction_fields_sensitive_value_supports_big_decimal() {
    struct DecimalValue(bigdecimal::BigDecimal);

    impl Redact for DecimalValue {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("DecimalValue", |fields| {
                fields.sensitive_value(Sensitivity::Medium, "coordinate", &self.0);
            });
        }
    }

    let value = DecimalValue(bigdecimal::BigDecimal::from(123));
    let enabled = Redactor::standard().redact(&value);
    let disabled = Redactor::new(RedactionPolicy::disabled()).redact(&value);

    assert!(!enabled.text().as_str().contains("123"));
    assert!(disabled.text().as_str().contains("123"));
}

/// Verifies map values use the level capability recursively when a key is
/// classified and remain ordinary values otherwise.
#[test]
fn test_redaction_fields_map_value_masks_recursive_leaves_by_key() {
    struct RecursiveMapValue {
        attributes: BTreeMap<String, Option<Vec<u32>>>,
    }

    impl Redact for RecursiveMapValue {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("RecursiveMapValue", |fields| {
                fields.map_value("attributes", &self.attributes);
            });
        }
    }

    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("secret_numbers");
        })
        .expect("field policy should build")
        .build()
        .expect("policy should build");
    let value = RecursiveMapValue {
        attributes: BTreeMap::from([
            ("public_numbers".to_owned(), Some(vec![1, 2])),
            ("secret_numbers".to_owned(), Some(vec![3, 4])),
        ]),
    };

    let output = Redactor::new(policy).redact(&value);
    assert!(
        output.text().as_str().contains("\"public_numbers\": Some([1, 2])"),
        "{}",
        output.text().as_str()
    );
    assert!(
        output
            .text()
            .as_str()
            .contains("\"secret_numbers\": Some([\"<redacted>\", \"<redacted>\"])"),
        "{}",
        output.text().as_str()
    );
    assert!(!output.text().as_str().contains("Some([3, 4])"));
}
