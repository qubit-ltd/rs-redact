// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`InputOutputLimit`](qubit_redact::InputOutputLimit).

use qubit_redact::DiagnosticBudgetError;
use qubit_redact::InputOutputLimit;
/// Verifies the default diagnostic limits remain finite and explicit.
#[test]
fn test_diagnostic_budget_default_uses_safe_limits() {
    let budget = InputOutputLimit::default();

    assert_eq!(budget.max_input_bytes(), 16 * 1024);
    assert_eq!(budget.max_output_bytes(), 64 * 1024);
}

/// Verifies that every invalid budget reports its exact invariant violation.
#[test]
fn test_diagnostic_budget_new_rejects_invalid_limits() {
    assert_eq!(
        InputOutputLimit::new(0, 64),
        Err(DiagnosticBudgetError::ZeroInput),
    );
    assert_eq!(
        InputOutputLimit::new(16, 0),
        Err(DiagnosticBudgetError::OutputTooSmall {
            minimum: InputOutputLimit::MIN_OUTPUT_BYTES,
            actual: 0,
        }),
    );
    assert_eq!(
        InputOutputLimit::new(16, InputOutputLimit::MIN_OUTPUT_BYTES - 1),
        Err(DiagnosticBudgetError::OutputTooSmall {
            minimum: InputOutputLimit::MIN_OUTPUT_BYTES,
            actual: InputOutputLimit::MIN_OUTPUT_BYTES - 1,
        }),
    );
}

/// Verifies that a valid budget preserves both hard byte limits.
#[test]
fn test_diagnostic_budget_new_preserves_limits() {
    let budget = InputOutputLimit::new(16, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the minimum diagnostic output budget should be valid");

    assert_eq!(budget.max_input_bytes(), 16);
    assert_eq!(
        budget.max_output_bytes(),
        InputOutputLimit::MIN_OUTPUT_BYTES
    );
}
