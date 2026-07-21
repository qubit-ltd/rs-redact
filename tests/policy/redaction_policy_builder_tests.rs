//! Tests for [`RedactionPolicyBuilder`](qubit_redact::RedactionPolicyBuilder).

use qubit_redact::{
    RedactionPolicy,
    Sensitivity,
};

/// Verifies the builder installs a configured field sensitivity.
#[test]
fn test_redaction_policy_builder_builds_configured_rule() {
    let policy = RedactionPolicy::empty_builder()
        .raise("tenant_secret", Sensitivity::High)
        .build()
        .expect("the configured rule should be valid");

    assert_eq!(
        policy.sensitivity_for("tenant_secret"),
        Some(Sensitivity::High),
    );
}
