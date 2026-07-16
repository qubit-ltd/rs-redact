// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`MaskPolicies`](qubit_sanitize::MaskPolicies).

use qubit_sanitize::{
    MaskPolicies,
    MaskPolicy,
    SensitivityLevel,
};

#[test]
fn test_mask_policies_new_and_level_accessors_select_requested_policy() {
    let low = MaskPolicy::fixed("low");
    let medium = MaskPolicy::fixed("medium");
    let high = MaskPolicy::fixed("high");
    let secret = MaskPolicy::fixed("secret");
    let mut policies = MaskPolicies::new(low, medium, high, secret);

    assert_eq!(
        policies.for_level(SensitivityLevel::Low).mask("value"),
        "low"
    );
    assert_eq!(
        policies.for_level(SensitivityLevel::Medium).mask("value"),
        "medium",
    );
    assert_eq!(
        policies.for_level(SensitivityLevel::High).mask("value"),
        "high",
    );
    assert_eq!(
        policies.for_level(SensitivityLevel::Secret).mask("value"),
        "secret",
    );

    *policies.for_level_mut(SensitivityLevel::High) = MaskPolicy::fixed("new");
    assert_eq!(
        policies.for_level(SensitivityLevel::High).mask("value"),
        "new"
    );
}

#[test]
fn test_mask_policies_set_and_with_policy_update_requested_level() {
    let mut policies = MaskPolicies::default();
    policies.set(SensitivityLevel::High, MaskPolicy::fixed("<high>"));
    assert_eq!(
        policies.for_level(SensitivityLevel::High).mask("secret"),
        "<high>",
    );

    let policies = policies
        .with_policy(SensitivityLevel::Secret, MaskPolicy::fixed("<secret>"));
    assert_eq!(
        policies.for_level(SensitivityLevel::Secret).mask("secret"),
        "<secret>",
    );
}

#[test]
fn test_mask_policies_clone_shares_until_mutated() {
    let original = MaskPolicies::default();
    let mut cloned = original.clone();

    assert!(std::ptr::eq(
        original.for_level(SensitivityLevel::Secret),
        cloned.for_level(SensitivityLevel::Secret),
    ));

    cloned.set(
        SensitivityLevel::Secret,
        MaskPolicy::fixed("<custom-secret>"),
    );

    assert_eq!(
        original.for_level(SensitivityLevel::Secret).mask("value"),
        "<redacted>",
    );
    assert_eq!(
        cloned.for_level(SensitivityLevel::Secret).mask("value"),
        "<custom-secret>",
    );
    assert!(!std::ptr::eq(
        original.for_level(SensitivityLevel::Secret),
        cloned.for_level(SensitivityLevel::Secret),
    ));
}
