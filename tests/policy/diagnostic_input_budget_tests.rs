// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for shared diagnostic input-budget consumption.

use qubit_redact::DiagnosticBudget;

/// Verifies a shared input budget becomes permanently exhausted after an
/// oversized reservation.
#[test]
fn test_diagnostic_input_budget_stops_after_oversized_reservation() {
    let mut budget = DiagnosticBudget::new(3, 64)
        .expect("the small diagnostic budget should be valid")
        .input_budget();

    assert!(budget.reserve(2));
    assert_eq!(budget.remaining_input_bytes(), 1);
    assert!(!budget.reserve(2));
    assert_eq!(budget.remaining_input_bytes(), 0);
    assert!(!budget.reserve(0));
}
