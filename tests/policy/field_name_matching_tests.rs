//! Tests for [`FieldNameMatching`](qubit_redact::FieldNameMatching).

use qubit_redact::FieldNameMatching;

/// Verifies both public matching modes remain distinct.
#[test]
fn test_field_name_matching_variants_are_distinct() {
    assert_ne!(
        FieldNameMatching::Exact,
        FieldNameMatching::ExactOrTokenSuffix,
    );
}
