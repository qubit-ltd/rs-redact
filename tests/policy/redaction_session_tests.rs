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
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
/// Verifies a diagnostic session shares cumulative input consumption.
#[test]
fn test_diagnostic_session_shares_input_budget() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(8)
        .max_output_bytes(64)
        .build()
        .expect("the test input/output limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let _ = session.redact_at(Sensitivity::Secret, "abc");
    let _ = session.redact_at(Sensitivity::Secret, "de");
    assert_eq!(session.remaining_input_bytes(), 3);
    assert_eq!(session.remaining_output_bytes(), 44);
}

/// Verifies exact exhaustion remains distinct from terminal closure and later
/// rejected input keeps producing charged fallbacks.
#[test]
fn test_diagnostic_session_accepts_zero_bytes_after_exact_consumption() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(3)
        .max_output_bytes(64)
        .build()
        .expect("the test input/output limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let _ = session.redact_at(Sensitivity::Secret, "abc");
    assert!(session.is_exhausted());
    assert_eq!(session.redact_at(Sensitivity::Secret, "").as_str(), "");
    assert_eq!(session.redact_at(Sensitivity::Secret, "x").as_str(), "<redacted>",);
    assert_eq!(session.redact_at(Sensitivity::Secret, "").as_str(), "<redacted>",);
    assert_eq!(session.remaining_output_bytes(), 34);
}

/// Verifies input exhaustion allows consecutive fail-closed markers while the
/// shared output budget can still contain them.
#[test]
fn test_diagnostic_session_allows_consecutive_input_fallbacks() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(3)
        .max_output_bytes(64)
        .build()
        .expect("the test input/output limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    assert_eq!(session.redact_at(Sensitivity::Secret, "abcd").as_str(), "<redacted>",);
    assert!(session.is_exhausted());
    assert_eq!(session.redact_at(Sensitivity::Secret, "efgh").as_str(), "<redacted>",);
    assert_eq!(session.remaining_input_bytes(), 3);
    assert_eq!(session.remaining_output_bytes(), 44);
}
