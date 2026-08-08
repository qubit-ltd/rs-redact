// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodyBudgetError`](qubit_redact::http::BodyBudgetError).

use qubit_redact::http::BodyBudgetError;
/// Verifies the minimum-output error describes both limits.
#[test]
fn test_body_budget_error_output_too_small_describes_limits() {
    assert_eq!(
        BodyBudgetError::OutputTooSmall {
            minimum: 11,
            actual: 10,
        }
        .to_string(),
        "body output budget must be at least 11 bytes, got 10",
    );
}
