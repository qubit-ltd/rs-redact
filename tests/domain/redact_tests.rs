// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the [`Redact`](qubit_redact::domain::Redact) domain contract.

use qubit_redact::RedactionCompletion;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::domain::Redact;
use qubit_redact::domain::RedactionWriter;
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
    let output = TestDomainValue.redacted();

    assert_eq!(output.text().as_str(), "TestDomainValue { secret: <redacted> }");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Exercises the writer's record, tuple, list, unit, trusted, and opaque
/// sensitive-field helpers through the supported domain contract.
#[test]
fn test_redaction_writer_structured_helper_shapes_and_opaque_access() {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    struct Structured<'a>(&'a AtomicUsize);

    impl Redact for Structured<'_> {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("Structured", |fields| {
                fields.unredacted("unit", || "Unit");
                fields.sensitive(Sensitivity::High, "secret", || {
                    self.0.fetch_add(1, Ordering::SeqCst);
                    "must not be read"
                });
                fields.nested("pair", &Pair);
                fields.list(|items| {
                    items.unredacted("", || 1_u8);
                    items.unredacted("", || 2_u8);
                });
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
        "Structured { unit: \"Unit\", secret: \"<redacted>\", pair: Pair(1, 2), [1, 2] }"
    );
}
