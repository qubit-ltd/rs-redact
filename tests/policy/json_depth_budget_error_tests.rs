//! Tests for JSON depth budget validation errors.

use qubit_redact::JsonDepthBudgetError;

#[test]
fn test_json_depth_budget_error_is_descriptive() {
    assert_eq!(
        JsonDepthBudgetError::ZeroDepth.to_string(),
        "JSON depth budget must be greater than zero",
    );
}
