// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactionPolicyBuilder`](qubit_redact::RedactionPolicyBuilder).

use qubit_redact::{
    DiagnosticBudget, MaskPolicy, PolicyError, PolicyLocation, RedactionPolicy, Sensitivity,
};

/// Verifies invalid field names fail at the setter that receives them.
#[test]
fn test_redaction_policy_builder_rejects_invalid_field_immediately() {
    assert_eq!(
        RedactionPolicy::builder()
            .raise("---", Sensitivity::High)
            .expect_err("an empty canonical field name must fail immediately"),
        PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules,
        },
    );
}

/// Verifies invalid mask policies fail at the setter that receives them.
#[test]
fn test_redaction_policy_builder_rejects_invalid_mask_immediately() {
    assert_eq!(
        RedactionPolicy::builder()
            .mask(Sensitivity::Secret, MaskPolicy::fixed(""))
            .expect_err("an empty fixed mask must fail immediately"),
        PolicyError::EmptyFixedReplacement {
            location: PolicyLocation::Rules,
            level: Sensitivity::Secret,
        },
    );
}

/// Verifies the builder installs a configured field sensitivity.
#[test]
fn test_redaction_policy_builder_builds_configured_rule() {
    let policy = RedactionPolicy::builder()
        .disable_floor()
        .raise("tenant_secret", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the configured rule should be valid");

    assert_eq!(
        policy.sensitivity_for("tenant_secret"),
        Some(Sensitivity::High),
    );
}

/// Verifies a diagnostic budget is a first-class immutable policy setting.
#[test]
fn test_redaction_policy_builder_preserves_diagnostic_budget() {
    let budget = DiagnosticBudget::new(128, 256).expect("the test budget is valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_budget(budget)
        .build()
        .expect("the policy should build");

    assert_eq!(policy.diagnostic_budget(), budget);
    assert_eq!(
        RedactionPolicy::builder_from(&policy)
            .build()
            .expect("copied policy should build"),
        policy,
    );
}

/// Verifies copied policies can revoke inherited exact and suffix allow rules.
#[test]
fn test_redaction_policy_builder_removes_inherited_allow_rules() {
    let base = RedactionPolicy::builder()
        .disable_floor()
        .raise("access_token", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .raise("session_token", Sensitivity::High)
        .expect("the test builder input should be valid")
        .allow_canonical_exact("access_token")
        .expect("the test builder input should be valid")
        .allow_suffix("session_token")
        .expect("the test builder input should be valid")
        .build()
        .expect("the base policy should be valid");
    let policy = RedactionPolicy::builder_from(&base)
        .remove_allow_canonical_exact("access-token")
        .expect("the test builder input should be valid")
        .remove_allow_suffix("session-token")
        .expect("the test builder input should be valid")
        .build()
        .expect("the rebuilt policy should be valid");

    assert_eq!(
        policy.sensitivity_for("access_token"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        policy.sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );
}

/// Verifies one operation removes every inherited allow rule.
#[test]
fn test_redaction_policy_builder_clears_inherited_allow_rules() {
    let base = RedactionPolicy::builder()
        .disable_floor()
        .raise("access_token", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .raise("session_token", Sensitivity::High)
        .expect("the test builder input should be valid")
        .allow_canonical_exact("access_token")
        .expect("the test builder input should be valid")
        .allow_suffix("session_token")
        .expect("the test builder input should be valid")
        .build()
        .expect("the base policy should be valid");
    let policy = RedactionPolicy::builder_from(&base)
        .clear_allow_rules()
        .build()
        .expect("the rebuilt policy should be valid");

    assert_eq!(
        policy.sensitivity_for("access_token"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        policy.sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );
}
