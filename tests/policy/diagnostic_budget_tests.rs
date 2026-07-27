// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`DiagnosticBudget`](qubit_redact::DiagnosticBudget).

use qubit_redact::{
    DiagnosticBudget,
    DiagnosticBudgetError,
};

/// Verifies the default diagnostic limits remain finite and explicit.
#[test]
fn test_diagnostic_budget_default_uses_safe_limits() {
    let budget = DiagnosticBudget::default();

    assert_eq!(budget.max_input_bytes(), 16 * 1024);
    assert_eq!(budget.max_output_bytes(), 64 * 1024);
}

/// Verifies that every invalid budget reports its exact invariant violation.
#[test]
fn test_diagnostic_budget_new_rejects_invalid_limits() {
    assert_eq!(
        DiagnosticBudget::new(0, 64),
        Err(DiagnosticBudgetError::ZeroInput),
    );
    assert_eq!(
        DiagnosticBudget::new(16, 0),
        Err(DiagnosticBudgetError::OutputTooSmall {
            minimum: DiagnosticBudget::MIN_OUTPUT_BYTES,
            actual: 0,
        }),
    );
    assert_eq!(
        DiagnosticBudget::new(16, DiagnosticBudget::MIN_OUTPUT_BYTES - 1),
        Err(DiagnosticBudgetError::OutputTooSmall {
            minimum: DiagnosticBudget::MIN_OUTPUT_BYTES,
            actual: DiagnosticBudget::MIN_OUTPUT_BYTES - 1,
        }),
    );
}

/// Verifies that a valid budget preserves both hard byte limits.
#[test]
fn test_diagnostic_budget_new_preserves_limits() {
    let budget = DiagnosticBudget::new(16, DiagnosticBudget::MIN_OUTPUT_BYTES)
        .expect("the minimum diagnostic output budget should be valid");

    assert_eq!(budget.max_input_bytes(), 16);
    assert_eq!(
        budget.max_output_bytes(),
        DiagnosticBudget::MIN_OUTPUT_BYTES
    );
}
