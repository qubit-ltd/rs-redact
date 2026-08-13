// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for operation-scoped redaction budgets.

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
/// Verifies a diagnostic session shares cumulative input consumption.
#[test]
fn test_diagnostic_session_shares_input_budget() {
    let limit = InputOutputLimit::new(8, 64)
        .expect("the test input/output limit should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(limit)
        .build()
        .expect("the test policy should build");
    let session = RedactionSession::diagnostic(&policy);

    assert!(session.consume_input(3));
    assert!(session.consume_input(2));
    assert_eq!(session.remaining_input_bytes(), 3);
    assert_eq!(session.remaining_output_bytes(), 64);
}

/// Verifies exact exhaustion remains distinct from terminal closure.
#[test]
fn test_diagnostic_session_accepts_zero_bytes_after_exact_consumption() {
    let limit = InputOutputLimit::new(3, 64)
        .expect("the test input/output limit should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(limit)
        .build()
        .expect("the test policy should build");
    let session = RedactionSession::diagnostic(&policy);

    assert!(session.consume_input(3));
    assert!(session.is_exhausted());
    assert!(session.consume_input(0));
    assert!(!session.consume_input(1));
    assert!(!session.consume_input(0));
}

/// Verifies input exhaustion still leaves room for a fail-closed marker.
#[test]
fn test_diagnostic_session_rejects_consumption_after_exhaustion() {
    let limit = InputOutputLimit::new(3, 64)
        .expect("the test input/output limit should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(limit)
        .build()
        .expect("the test policy should build");
    let session = RedactionSession::diagnostic(&policy);

    assert!(!session.consume_input(4));
    assert!(session.is_exhausted());
    assert_eq!(session.remaining_input_bytes(), 3);
    assert_eq!(session.remaining_output_bytes(), 64);
}
