// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`DiagnosticLogBuilder`](qubit_redact::DiagnosticLogBuilder).

use std::fmt;

use qubit_redact::DiagnosticLogBuilder;
use qubit_redact::DiagnosticWriteStatus;
use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
/// Verifies formatted fragments share one escaped output budget.
#[test]
fn test_diagnostic_builder_escapes_and_shares_output_budget() {
    let budget = InputOutputLimit::new(128, 40).expect("the diagnostic budget should be valid");
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder
            .push_fmt(format_args!("prefix\n"))
            .expect("formatting should succeed"),
        DiagnosticWriteStatus::Complete,
    );
    assert_eq!(
        builder.push_fmt(format_args!(
            "{}",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
        )),
        Ok(DiagnosticWriteStatus::Truncated),
    );
    assert!(builder.is_truncated());
    assert_eq!(
        builder.finish().as_str(),
        "prefix\\nabcdefghijklmnopqrstu<truncated>",
    );
}

/// Verifies a safe fragment can be appended without losing the shared bound.
#[test]
fn test_diagnostic_builder_appends_safe_text() {
    let budget = InputOutputLimit::new(128, 64).expect("the diagnostic budget should be valid");
    let safe = Redactor::default()
        .redact_field("message", "line\nnext")
        .escape_for_log();
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(builder.push_safe(&safe), DiagnosticWriteStatus::Complete,);
    assert_eq!(builder.finish().as_str(), "line\\nnext");
}

/// Verifies field helpers share session accounting and escape visible controls.
#[test]
fn test_diagnostic_builder_pushes_redacted_fields_with_shared_session() {
    let budget = InputOutputLimit::new(18, 64).expect("the diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the diagnostic policy should build");
    let redactor = qubit_redact::Redactor::new(policy);
    let mut session = redactor.session();
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder.push_redacted_field(&mut session, "message", "line\nnext"),
        DiagnosticWriteStatus::Complete,
    );
    assert_eq!(
        builder.push_redacted_field(&mut session, "password", "raw"),
        DiagnosticWriteStatus::Complete,
    );

    assert_eq!(builder.finish().as_str(), "line\\nnext<redacted>");
    assert!(session.is_exhausted());
}

/// Verifies explicit-level helpers use the configured mask and shared budget.
#[test]
fn test_diagnostic_builder_pushes_explicitly_sensitive_values() {
    let budget = InputOutputLimit::new(128, 64).expect("the diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the diagnostic policy should build");
    let redactor = qubit_redact::Redactor::new(policy);
    let mut session = redactor.session();
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder.push_redacted_at(&mut session, Sensitivity::Secret, "raw\nsecret",),
        DiagnosticWriteStatus::Complete,
    );
    assert_eq!(builder.finish().as_str(), "<redacted>");
}

/// Verifies safe fragments report truncation both when they exhaust output and
/// when a later append is skipped.
#[test]
fn test_diagnostic_builder_safe_append_reports_current_and_prior_truncation() {
    let budget = InputOutputLimit::new(128, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the diagnostic budget should be valid");
    let safe = Redactor::default()
        .redact_field(
            "message",
            "payload that cannot fit and is definitely longer than the marker",
        )
        .escape_for_log();
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(builder.push_safe(&safe), DiagnosticWriteStatus::Truncated);
    let is_truncated: fn(&DiagnosticLogBuilder) -> bool = DiagnosticLogBuilder::is_truncated;
    assert!(is_truncated(&builder));
    assert_eq!(builder.push_safe(&safe), DiagnosticWriteStatus::Truncated);
}

/// Verifies formatting arguments are not evaluated after truncation.
#[test]
fn test_diagnostic_builder_stops_after_truncation() {
    struct PanicDisplay;

    impl fmt::Display for PanicDisplay {
        fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("the formatter must not be evaluated after truncation");
        }
    }

    let budget = InputOutputLimit::new(128, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the diagnostic budget should be valid");
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder.push_fmt(format_args!(
            "payload that cannot fit and is definitely longer than the marker"
        )),
        Ok(DiagnosticWriteStatus::Truncated),
    );
    assert_eq!(
        builder.push_fmt(format_args!("{}", PanicDisplay)),
        Ok(DiagnosticWriteStatus::Truncated),
    );
}

/// Verifies an independent formatter error is not reported as truncation.
#[test]
fn test_diagnostic_builder_propagates_formatter_error() {
    struct FailingDisplay;

    impl fmt::Display for FailingDisplay {
        fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            Err(fmt::Error)
        }
    }

    let budget = InputOutputLimit::new(128, 64).expect("the diagnostic budget should be valid");
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder.push_fmt(format_args!("{}", FailingDisplay)),
        Err(fmt::Error),
    );
    assert!(!builder.is_truncated());
}
