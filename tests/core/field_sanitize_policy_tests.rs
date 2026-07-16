// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`FieldSanitizePolicy`](qubit_sanitize::FieldSanitizePolicy).

use qubit_sanitize::{
    FieldSanitizePolicy,
    MaskPolicies,
    MaskPolicy,
    SensitiveFields,
    SensitivityLevel,
};

#[test]
fn test_field_sanitize_policy_new_and_accessors_expose_owned_components() {
    let mut fields = SensitiveFields::new();
    fields.insert("custom", SensitivityLevel::Low);
    let policies = MaskPolicies::default()
        .with_policy(SensitivityLevel::Low, MaskPolicy::fixed("low"));
    let mut policy = FieldSanitizePolicy::new(fields, policies);

    assert_eq!(
        policy.sensitive_fields().level_for("custom"),
        Some(SensitivityLevel::Low),
    );
    assert_eq!(
        policy
            .mask_policies()
            .for_level(SensitivityLevel::Low)
            .mask("value"),
        "low",
    );

    policy
        .sensitive_fields_mut()
        .insert("second", SensitivityLevel::High);
    policy
        .mask_policies_mut()
        .set(SensitivityLevel::High, MaskPolicy::fixed("high"));
    assert_eq!(
        policy.sensitive_fields().level_for("second"),
        Some(SensitivityLevel::High),
    );
    assert_eq!(
        policy
            .mask_policies()
            .for_level(SensitivityLevel::High)
            .mask("value"),
        "high",
    );
}

#[test]
fn test_field_sanitize_policy_builders_replace_owned_components() {
    let mut fields = SensitiveFields::new();
    fields.insert("replacement", SensitivityLevel::Secret);
    let policies = MaskPolicies::default()
        .with_policy(SensitivityLevel::Secret, MaskPolicy::fixed("secret"));

    let policy = FieldSanitizePolicy::empty()
        .with_sensitive_fields(fields)
        .with_mask_policies(policies);

    assert_eq!(
        policy.sensitive_fields().level_for("replacement"),
        Some(SensitivityLevel::Secret),
    );
    assert_eq!(
        policy
            .mask_policies()
            .for_level(SensitivityLevel::Secret)
            .mask("value"),
        "secret",
    );
}
