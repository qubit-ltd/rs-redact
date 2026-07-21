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
