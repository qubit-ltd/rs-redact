// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for shared HTTP diagnostic budget helpers.

use qubit_redact::{
    RedactionPolicy,
    RedactionSession,
    http::{
        BodyCapture,
        BodyRedactionReason,
        BodyRedactionStatus,
        HttpRedactor,
        InputOutputLimit,
    },
};

/// Verifies diagnostic input limits return the fixed safe marker.
#[test]
fn test_diagnostic_input_limit_returns_fixed_marker() {
    let budget = InputOutputLimit::new(16, 128)
        .expect("test diagnostic budget should satisfy minimums");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("HTTP policy should be valid");
    let redactor = HttpRedactor::new(policy);

    assert_eq!(
        redactor
            .redact_url_str("https://example.test/?password=secret")
            .as_ref(),
        "<redacted: diagnostic limit exceeded>",
    );
}

/// Verifies session fallback markers are charged to the cumulative output
/// budget and cannot be emitted repeatedly after exhaustion.
#[test]
fn test_session_fallback_markers_respect_cumulative_output_limit() {
    let budget = InputOutputLimit::new(8, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the marker-sized diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("HTTP policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let session = RedactionSession::diagnostic(redactor.policy());

    let first = redactor.redact_url_str_with_session(
        "https://example.test/?password=secret",
        &session,
    );
    let second = redactor.redact_url_str_with_session(
        "https://example.test/?password=secret",
        &session,
    );

    assert_eq!(
        first.as_str(),
        "<redacted: diagnostic limit exceeded>",
    );
    assert!(second.as_str().is_empty());
    assert_eq!(session.remaining_output_bytes(), 0);
    assert!(
        first
            .as_str()
            .len()
            .saturating_add(second.as_str().len())
            <= budget.max_output_bytes()
    );
}

/// Verifies a body rejected by the shared diagnostic budget is not reported as
/// an unsupported media type.
#[test]
fn test_session_body_input_limit_reports_budget_failure() {
    let budget = InputOutputLimit::new(8, 128)
        .expect("test diagnostic budget should satisfy minimums");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("HTTP policy should be valid");
    let redactor = HttpRedactor::new(policy);
    let session = RedactionSession::diagnostic(redactor.policy());

    let result = redactor.redact_body_with_session(
        BodyCapture::complete(br#"{"password":"secret"}"#),
        None,
        &session,
    );

    assert_eq!(
        result.status(),
        BodyRedactionStatus::Redacted(
            BodyRedactionReason::DiagnosticBudgetExceeded,
        ),
    );
}
