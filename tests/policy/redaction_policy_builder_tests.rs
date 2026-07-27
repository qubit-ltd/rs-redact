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
