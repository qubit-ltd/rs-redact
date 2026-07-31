// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`DiagnosticLogBuilder`](qubit_redact::DiagnosticLogBuilder).

use std::fmt;

use qubit_redact::{
    DiagnosticBudget,
    DiagnosticLogBuilder,
    DiagnosticWriteStatus,
    Redactor,
};

/// Verifies formatted fragments share one escaped output budget.
#[test]
fn test_diagnostic_builder_escapes_and_shares_output_budget() {
    let budget = DiagnosticBudget::new(128, 40)
        .expect("the diagnostic budget should be valid");
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
    let budget = DiagnosticBudget::new(128, 64)
        .expect("the diagnostic budget should be valid");
    let safe = Redactor::default()
        .redact("message", "line\nnext")
        .escape_for_log();
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(builder.push_safe(&safe), DiagnosticWriteStatus::Complete,);
    assert_eq!(builder.finish().as_str(), "line\\nnext");
}

/// Verifies input accounting remains shared with downstream redactors.
#[test]
fn test_diagnostic_builder_exposes_shared_input_budget() {
    let budget = DiagnosticBudget::new(3, 64)
        .expect("the diagnostic budget should be valid");
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert!(builder.input_budget().reserve(2));
    assert!(!builder.input_budget().reserve(2));
    assert_eq!(builder.input_budget().remaining_input_bytes(), 0);
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

    let budget = DiagnosticBudget::new(128, DiagnosticBudget::MIN_OUTPUT_BYTES)
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

    let budget = DiagnosticBudget::new(128, 64)
        .expect("the diagnostic budget should be valid");
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder.push_fmt(format_args!("{}", FailingDisplay)),
        Err(fmt::Error),
    );
    assert!(!builder.is_truncated());
}
