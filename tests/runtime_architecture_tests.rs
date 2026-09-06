// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression checks for the transaction runtime ownership boundary.

use std::cell::Cell;

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// Structured value whose secret accessor records any unexpected evaluation.
struct LazySecret<'state>(&'state Cell<bool>);

impl Redact for LazySecret<'_> {
    /// Writes one secret field through the field-specific capability.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("LazySecret", |fields| {
            fields.sensitive(Sensitivity::Secret, "password", || {
                self.0.set(true);
                "raw-secret"
            });
        });
    }
}

/// Composer, batch diagnostics, and inspection publish distinct safe models
/// without evaluating a secret accessor.
#[test]
fn test_publication_modes_preserve_their_behavioral_contracts() {
    let accessed = Cell::new(false);
    let value = LazySecret(&accessed);
    let redactor = Redactor::strict();

    let composed = redactor.text_composer().value(&value).finish();
    let mut batch = redactor.batch();
    let handle = batch.redact_value(&value);
    let diagnostics = batch.finish_for_diagnostics("<redaction incomplete>");
    let inspection = redactor.inspect(&value).expect("inspection should be conclusive");

    assert!(!composed.text().as_str().contains("raw-secret"));
    assert!(!diagnostics.text(handle).as_str().contains("raw-secret"));
    assert_eq!(inspection.max_sensitivity(), Some(Sensitivity::Secret));
    assert!(!accessed.get());
}

/// An exactly filled output budget closes the transaction before a later
/// domain value can evaluate its accessor.
#[test]
fn test_output_budget_is_owned_by_the_parent_text_transaction() {
    let accessed = Cell::new(false);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(4);
        })
        .expect("the output limit should be valid")
        .build()
        .expect("the bounded policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .literal("safe")
        .value(&LazySecret(&accessed))
        .finish();

    assert_eq!(output.text().as_str(), "safe");
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(!accessed.get());
}

/// Invalid JSON is represented by safe text and machine-readable provenance,
/// without constraining the private parser implementation.
#[cfg(feature = "json")]
#[test]
fn test_json_contract_preserves_invalid_input_provenance() {
    let output = Redactor::strict().redact_json(r#"{"password":"raw-secret""#);

    assert!(!output.text().as_str().contains("raw-secret"));
    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
}
