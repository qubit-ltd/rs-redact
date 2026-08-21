// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Regression coverage for publication-model-local output budgets.

use std::cell::Cell;
use std::ffi::OsStr;

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

fn create_one_byte_redactor() -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("the test limit draft should build")
        .build()
        .expect("the test policy should build");
    Redactor::new(policy)
}

#[test]
fn composer_stops_later_adapter_after_output_exhaustion() {
    let later_called = Cell::new(false);
    let output = create_one_byte_redactor()
        .text_composer()
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("client"))]);
        })
        .env(|_| later_called.set(true))
        .finish();

    assert_eq!(
        output.summary().completion(),
        RedactionCompletion::Exhausted
    );
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
    assert!(!later_called.get());
}

#[test]
fn batch_stops_later_item_after_output_exhaustion() {
    let mut batch = create_one_byte_redactor().batch();
    let first = batch.redact_argv([ArgvItem::plain(OsStr::new("client"))]);
    let second = batch.redact_env("MODE", "debug");
    let output = batch.finish();

    assert_eq!(
        output.summary().completion(),
        RedactionCompletion::Exhausted
    );
    assert_eq!(
        output
            .resolve(first)
            .expect("first item resolves")
            .summary()
            .completion(),
        RedactionCompletion::Exhausted
    );
    assert_eq!(
        output
            .resolve(second)
            .expect("exhausted item resolves")
            .summary()
            .completion(),
        RedactionCompletion::Exhausted
    );
}

#[test]
fn composer_and_batch_own_independent_budget_ledgers() {
    let redactor = create_one_byte_redactor();
    let text = redactor.text_composer().literal("x").finish();
    let mut batch = redactor.batch();
    let item = batch.redact_field("name", "x");
    let output = batch.finish();

    assert_eq!(text.text().as_str(), "x");
    assert_eq!(text.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(
        output
            .resolve(item)
            .expect("batch item resolves")
            .text()
            .as_str(),
        "x"
    );
}
