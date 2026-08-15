// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for shared diagnostic input-budget consumption.

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
/// Verifies an oversized reservation closes input without preventing later
/// fail-closed output while output capacity remains.
#[test]
fn test_diagnostic_input_budget_stops_after_oversized_reservation() {
    let limit = InputOutputLimit::new(3, 64)
        .expect("the small diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let _ = session.redact_at(Sensitivity::Secret, "ab");
    assert_eq!(session.remaining_input_bytes(), 1);
    let _ = session.redact_at(Sensitivity::Secret, "cd");
    assert_eq!(session.remaining_input_bytes(), 1);
    assert_eq!(
        session.redact_at(Sensitivity::Secret, "").as_str(),
        "<redacted>",
    );
    assert_eq!(session.remaining_input_bytes(), 1);
}
