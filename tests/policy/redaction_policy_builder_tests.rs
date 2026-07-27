// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactionPolicyBuilder`](qubit_redact::RedactionPolicyBuilder).

use qubit_redact::{DiagnosticBudget, RedactionPolicy, Sensitivity};

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

/// Verifies a diagnostic budget is a first-class immutable policy setting.
#[test]
fn test_redaction_policy_builder_preserves_diagnostic_budget() {
    let budget = DiagnosticBudget::new(128, 256).expect("the test budget is valid");
    let policy = RedactionPolicy::empty_builder()
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
    let base = RedactionPolicy::empty_builder()
        .raise("access_token", Sensitivity::Secret)
        .raise("session_token", Sensitivity::High)
        .allow_exact("access_token")
        .allow_suffix("session_token")
        .build()
        .expect("the base policy should be valid");
    let policy = RedactionPolicy::builder_from(&base)
        .remove_allow_exact("access-token")
        .remove_allow_suffix("session-token")
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
    let base = RedactionPolicy::empty_builder()
        .raise("access_token", Sensitivity::Secret)
        .raise("session_token", Sensitivity::High)
        .allow_exact("access_token")
        .allow_suffix("session_token")
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
