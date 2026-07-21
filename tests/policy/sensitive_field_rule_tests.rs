//! Tests for [`SensitiveFieldRule`](qubit_redact::SensitiveFieldRule) views.

use qubit_redact::{
    RedactionPolicy,
    Sensitivity,
};

/// Verifies a configured sensitive rule exposes its field and level.
#[test]
fn test_sensitive_field_rule_exposes_configuration() {
    let policy = std::hint::black_box(
        RedactionPolicy::empty_builder()
            .raise("tenant_secret", Sensitivity::High)
            .build()
            .expect("the configured rule should be valid"),
    );
    let rule = policy
        .sensitive_rules()
        .next()
        .expect("the configured sensitive rule should be visible");

    assert_eq!(rule.field(), "tenantsecret");
    assert_eq!(rule.sensitivity(), Sensitivity::High);
}
