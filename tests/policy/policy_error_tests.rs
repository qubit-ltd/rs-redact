//! Tests for [`PolicyError`](qubit_redact::PolicyError).

use qubit_redact::PolicyError;

/// Verifies an empty canonical name reports the precise validation error.
#[test]
fn test_policy_error_empty_field_name_has_stable_display() {
    assert_eq!(
        PolicyError::EmptyFieldName.to_string(),
        "field name is empty after canonicalization",
    );
}
