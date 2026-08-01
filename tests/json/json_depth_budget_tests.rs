// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for validated JSON recursion-depth budgets.

use qubit_redact::{
    JsonDepthBudget,
    JsonDepthBudgetError,
    RedactionPolicy,
};

/// Verifies JSON depth budgets are positive and have a finite default.
#[test]
fn test_json_depth_budget_validates_positive_depth() {
    assert_eq!(
        JsonDepthBudget::new(0),
        Err(JsonDepthBudgetError::ZeroDepth),
    );
    assert_eq!(
        JsonDepthBudgetError::ZeroDepth.to_string(),
        "JSON depth budget must be greater than zero",
    );
    assert_eq!(
        JsonDepthBudget::default().max_depth(),
        JsonDepthBudget::DEFAULT_MAX_DEPTH,
    );
}

/// Verifies policies retain custom JSON depth budgets across immutable copies.
#[test]
fn test_redaction_policy_preserves_json_depth_budget() {
    let budget = JsonDepthBudget::new(3).expect("the depth budget is valid");
    let policy = RedactionPolicy::empty_builder()
        .json_depth_budget(budget)
        .build()
        .expect("the policy should build");
    let copied = RedactionPolicy::builder_from(&policy)
        .build()
        .expect("the copied policy should build");

    assert_eq!(policy.json_depth_budget(), budget);
    assert_eq!(copied, policy);
}
