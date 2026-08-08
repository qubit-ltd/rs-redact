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
use qubit_redact::RedactionSession;
/// Verifies a shared input budget becomes permanently exhausted after an
/// oversized reservation.
#[test]
fn test_diagnostic_input_budget_stops_after_oversized_reservation() {
    let limit = InputOutputLimit::new(3, 64)
        .expect("the small diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .ordinary_operation(limit)
        .build()
        .expect("the test policy should build");
    let budget = RedactionSession::operation(&policy);

    assert!(budget.consume_input(2));
    assert_eq!(budget.remaining_input_bytes(), 1);
    assert!(!budget.consume_input(2));
    assert_eq!(budget.remaining_input_bytes(), 0);
    assert!(!budget.consume_input(0));
}
