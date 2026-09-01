// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Transactional publication contracts for composer and batch.

use std::ffi::OsStr;
use std::panic::AssertUnwindSafe;

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

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
        output.resolve(first).expect("first item resolves").text().as_str(),
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

    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
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

#[test]
fn batch_panic_invalidates_handles_created_before_rollback() {
    let mut batch = Redactor::strict().batch();
    let stale = batch.redact_field("password", "raw-secret");
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = batch.redact_value(&PanickingValue);
    }));
    assert!(result.is_err());

    let current = batch.redact_field("password", "raw-secret");
    let output = batch.finish();
    assert!(output.resolve(stale).is_err());
    assert_eq!(
        output
            .resolve(current)
            .expect("post-panic item resolves")
            .text()
            .as_str(),
        "<redacted>"
    );
}

#[test]
fn process_composer_batch_and_one_shot_publish_equivalent_safe_text() {
    let redactor = Redactor::standard();
    let program = OsStr::new("client");
    let arguments = [ArgvItem::plain(OsStr::new("--password=raw-secret"))];
    let variables = [(OsStr::new("PASSWORD"), OsStr::new("raw-secret"))];

    let composer = redactor
        .text_composer()
        .process(|process| {
            process.command(program, arguments, variables);
        })
        .finish();

    let mut batch = redactor.batch();
    let handle = batch.redact_process(program, arguments, variables);
    let batch = batch.finish();

    let one_shot = redactor.redact_process(program, arguments, variables);
    let batch_text = batch.resolve(handle).expect("batch process resolves").text().as_str();

    assert_eq!(composer.text().as_str(), batch_text);
    assert_eq!(composer.text().as_str(), one_shot.text().as_str());
    assert!(!composer.text().as_str().contains("raw-secret"));
}

#[test]
fn process_composer_records_environment_collection_limit_after_argv() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limits should build")
        .build()
        .expect("policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .process(|process| {
            process.command(
                OsStr::new("client"),
                [],
                [(OsStr::new("PASSWORD"), OsStr::new("must-not-be-rendered"))],
            );
        })
        .finish();

    assert_eq!(output.text().as_str(), "[\"client\"]");
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!output.text().as_str().contains("must-not-be-rendered"));
}

#[test]
fn process_batch_records_environment_collection_limit_after_argv() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limits should build")
        .build()
        .expect("policy should build");
    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_process(
        OsStr::new("client"),
        [],
        [(OsStr::new("PASSWORD"), OsStr::new("must-not-be-rendered"))],
    );
    let output = batch.finish();
    let item = output.resolve(handle).expect("process handle publishes");

    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert!(
        item.summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!item.text().as_str().contains("must-not-be-rendered"));
}
