// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Transactional publication contracts for composer and batch.

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use std::panic::AssertUnwindSafe;

struct SafeValue;

impl Redact for SafeValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("SafeValue", |fields| {
            fields.unredacted("name", || "Ada");
        });
    }
}

struct PanickingValue;

impl Redact for PanickingValue {
    fn write_redacted(&self, _: &mut RedactionWriter<'_>) {
        panic!("test-only redaction panic");
    }
}

#[test]
fn composer_publishes_one_ordered_text() {
    let output = Redactor::strict()
        .text_composer()
        .literal("password=")
        .field("password", "raw-secret")
        .literal(" value=")
        .value(&SafeValue)
        .finish();

    assert!(output.text().as_str().contains("password=<redacted>"));
    assert!(output.text().as_str().contains("SafeValue"));
    assert!(!output.text().as_str().contains("raw-secret"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

#[test]
fn batch_resolves_items_only_from_its_own_output() {
    let mut batch = Redactor::standard().batch();
    let first = batch.redact_field("name", "Ada");
    let second = batch.redact_value(&SafeValue);
    let output = batch.finish();

    assert_eq!(
        output
            .resolve(first)
            .expect("first item resolves")
            .text()
            .as_str(),
        "Ada"
    );
    assert!(
        output
            .resolve(second)
            .expect("value item resolves")
            .text()
            .as_str()
            .contains("SafeValue")
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

#[test]
fn batch_rejects_handle_from_different_batch() {
    let mut first = Redactor::standard().batch();
    let handle = first.redact_field("name", "Ada");
    let _ = first.finish();

    let second = Redactor::standard().batch().finish();
    assert!(second.resolve(handle).is_err());
}

#[test]
fn output_limit_is_observable_without_publishing_raw_input() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("limits should build")
        .build()
        .expect("policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .field("password", "raw-secret")
        .finish();

    assert_eq!(
        output.summary().completion(),
        RedactionCompletion::Exhausted
    );
    assert!(!output.text().as_str().contains("raw-secret"));
}

#[test]
fn batch_recovers_from_user_redaction_panic_without_publishing_partial_item() {
    let mut batch = Redactor::strict().batch();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = batch.redact_value(&PanickingValue);
    }));
    assert!(result.is_err());

    let handle = batch.redact_field("password", "raw-secret");
    let output = batch.finish();
    assert_eq!(
        output
            .resolve(handle)
            .expect("post-panic item resolves")
            .text()
            .as_str(),
        "<redacted>"
    );
}
