//! Tests for [`AllowRule`](qubit_redact::AllowRule) views.

use qubit_redact::{
    FieldNameMatching,
    RedactionPolicy,
};

/// Verifies an exact allow rule is exposed with its canonical field name.
#[test]
fn test_allow_rule_exposes_exact_field_and_matching_mode() {
    let policy = RedactionPolicy::empty_builder()
        .allow_exact("public-token")
        .build()
        .expect("the allow rule should be valid");
    let rule = policy
        .allow_rules()
        .next()
        .expect("the configured allow rule should be visible");

    assert_eq!(rule.field(), "publictoken");
    assert_eq!(rule.matching(), FieldNameMatching::Exact);
}
