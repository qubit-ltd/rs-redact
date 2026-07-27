// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`DiagnosticBudgetError`](qubit_redact::DiagnosticBudgetError).

use std::error::Error;

use qubit_redact::DiagnosticBudgetError;

/// Verifies diagnostic budget errors implement the standard error contract.
#[test]
fn test_diagnostic_budget_error_describes_invalid_limits() {
    let zero_input = DiagnosticBudgetError::ZeroInput;
    let output_too_small = DiagnosticBudgetError::OutputTooSmall {
        minimum: 38,
        actual: 37,
    };

    assert_eq!(
        zero_input.to_string(),
        "diagnostic input budget must be greater than zero",
    );
    assert_eq!(
        output_too_small.to_string(),
        "diagnostic output budget must be at least 38 bytes, got 37",
    );
    assert!(zero_input.source().is_none());
    assert!(output_too_small.source().is_none());
}
