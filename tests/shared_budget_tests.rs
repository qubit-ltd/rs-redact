// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression coverage for the session-wide output budget.

use std::cell::Cell;
use std::ffi::OsStr;

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionSessionOutput;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

/// Creates a redactor whose output ceiling cannot hold a fallback marker.
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

/// Verifies the exhausted session result and later-operation sentinel.
fn assert_exhausted_before_later_operation(output: RedactionSessionOutput, later_called: &Cell<bool>) {
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(!later_called.get());
}

/// Verifies that an argv fallback which cannot fit closes the whole
/// transaction before later closures can inspect their inputs.
#[test]
fn test_format_exhaustion_skips_following_operation() {
    let later_called = Cell::new(false);
    let mut session = create_one_byte_redactor().session();

    let output = session
        .argv(|argv| {
            argv.items([ArgvItem::plain(OsStr::new("client"))]);
        })
        .env(|_| later_called.set(true))
        .finish();

    assert_exhausted_before_later_operation(output, &later_called);
}

/// Verifies environment rendering closes the transaction when its safe
/// fallback cannot fit.
#[test]
fn test_env_exhaustion_skips_following_operation() {
    let later_called = Cell::new(false);
    let mut session = create_one_byte_redactor().session();

    let output = session
        .env(|env| {
            env.pair("PASSWORD", "secret");
        })
        .argv(|_| later_called.set(true))
        .finish();

    assert_exhausted_before_later_operation(output, &later_called);
}

/// Verifies process rendering inherits argv's exhausted transaction state.
#[test]
fn test_process_exhaustion_skips_following_operation() {
    let later_called = Cell::new(false);
    let mut session = create_one_byte_redactor().session();

    let output = session
        .process(|process| {
            process.arguments([ArgvItem::plain(OsStr::new("client"))]);
        })
        .env(|_| later_called.set(true))
        .finish();

    assert_exhausted_before_later_operation(output, &later_called);
}

/// Verifies that an exhausted item operation also closes the aggregate
/// transaction before later adapter closures run.
#[test]
fn test_exhausted_item_skips_following_operation() {
    let later_called = Cell::new(false);
    let mut session = create_one_byte_redactor().session();

    let handle = session.redact_argv([ArgvItem::plain(OsStr::new("client"))]);
    let output = session.env(|_| later_called.set(true)).finish();

    assert_exhausted_before_later_operation(output.clone(), &later_called);
    assert_eq!(
        output
            .resolve(handle)
            .expect("the exhausted item handle should resolve")
            .summary()
            .completion(),
        RedactionCompletion::Exhausted
    );
}

/// Verifies URI rendering closes the transaction when its safe fallback does
/// not fit.
#[cfg(feature = "uri")]
#[test]
fn test_uri_exhaustion_skips_following_operation() {
    let later_called = Cell::new(false);
    let mut session = create_one_byte_redactor().session();

    let output = session
        .uri(|uri| {
            uri.value("https://example.test/path?token=secret");
        })
        .env(|_| later_called.set(true))
        .finish();

    assert_exhausted_before_later_operation(output, &later_called);
}

/// Verifies JSON rendering closes the transaction when its safe fallback does
/// not fit.
#[cfg(feature = "json")]
#[test]
fn test_json_exhaustion_skips_following_operation() {
    let later_called = Cell::new(false);
    let mut session = create_one_byte_redactor().session();

    let output = session
        .json(|json| {
            json.text(r#"{"token":"secret"}"#);
        })
        .env(|_| later_called.set(true))
        .finish();

    assert_exhausted_before_later_operation(output, &later_called);
}

/// Verifies HTTP URL rendering closes the transaction when its safe fallback
/// does not fit.
#[cfg(feature = "http")]
#[test]
fn test_http_url_exhaustion_skips_following_operation() {
    let later_called = Cell::new(false);
    let mut session = create_one_byte_redactor().session();

    let output = session
        .http(|http| {
            http.url("https://example.test/path?token=secret");
        })
        .env(|_| later_called.set(true))
        .finish();

    assert_exhausted_before_later_operation(output, &later_called);
}
