// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression coverage for bounded domain rendering.
//!
//! The former lazy `Display` views were deliberately removed: a redacted value
//! is now published only by a completed transaction.  This test keeps the
//! important bounded-rendering guarantee at that new boundary.

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;

/// A domain value with a representation larger than the test transaction's
/// output budget.
struct SafeRecord;

impl Redact for SafeRecord {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("SafeRecord", |fields| {
            fields.unredacted("id", || 7_u64);
            fields.unredacted("label", || "visible diagnostic label");
        });
    }
}

/// Verifies multiple domain renderings draw from the same transaction output
/// budget and publish a bounded exhausted result once the second rendering is
/// attempted after the first has closed the transaction.
#[test]
fn test_domain_rendering_uses_one_bounded_transaction_output_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(24);
        })
        .expect("the limit draft should build")
        .build()
        .expect("the policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .value(&SafeRecord)
        .value(&SafeRecord)
        .finish();

    assert!(output.text().as_str().len() <= 24);
    assert_eq!(
        output.summary().usage().output_bytes(),
        output.text().as_str().len()
    );
    assert_eq!(
        output.summary().completion(),
        RedactionCompletion::Exhausted
    );
}
