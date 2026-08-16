// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodyBudget`](qubit_redact::http::BodyBudget).

use qubit_redact::http::BodyBudget;
use qubit_redact::http::BodyBudgetError;
/// Verifies budget errors implement the standard error contract precisely.
#[test]
fn test_body_budget_error_display_describes_invalid_limit() {
    assert_eq!(
        BodyBudgetError::ZeroInput.to_string(),
        "body input budget must be greater than zero",
    );
    assert_eq!(
        BodyBudgetError::OutputTooSmall {
            minimum: 11,
            actual: 10,
        }
        .to_string(),
        "body output budget must be at least 11 bytes, got 10",
    );
}

/// Verifies that every invalid budget reports its exact invariant violation.
#[test]
fn test_body_budget_new_rejects_invalid_limits() {
    assert_eq!(
        BodyBudget::builder()
            .max_input_bytes(0)
            .max_output_bytes(64)
            .build(),
        Err(BodyBudgetError::ZeroInput)
    );
    assert_eq!(
        BodyBudget::builder()
            .max_input_bytes(16)
            .max_output_bytes(0)
            .build(),
        Err(BodyBudgetError::OutputTooSmall {
            minimum: BodyBudget::MIN_OUTPUT_BYTES,
            actual: 0,
        }),
    );
    assert_eq!(
        BodyBudget::builder()
            .max_input_bytes(16)
            .max_output_bytes(BodyBudget::MIN_OUTPUT_BYTES - 1)
            .build(),
        Err(BodyBudgetError::OutputTooSmall {
            minimum: BodyBudget::MIN_OUTPUT_BYTES,
            actual: BodyBudget::MIN_OUTPUT_BYTES - 1,
        }),
    );
}

/// Verifies that a valid budget preserves both hard byte limits.
#[test]
fn test_body_budget_new_preserves_limits() {
    let budget = BodyBudget::builder()
        .max_input_bytes(16)
        .max_output_bytes(BodyBudget::MIN_OUTPUT_BYTES)
        .build()
        .expect("the minimum output budget should be valid");

    assert_eq!(budget.max_input_bytes(), 16);
    assert_eq!(budget.max_output_bytes(), BodyBudget::MIN_OUTPUT_BYTES,);
}
