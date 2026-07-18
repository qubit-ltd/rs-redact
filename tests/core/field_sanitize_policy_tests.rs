// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`FieldSanitizePolicy`](qubit_sanitize::FieldSanitizePolicy).

use qubit_sanitize::{
    FieldSanitizePolicy,
    FieldSanitizer,
    MaskPolicies,
    MaskPolicy,
    NameMatchMode,
    SensitiveFieldPreset,
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

    policy.insert_sensitive_field("second", SensitivityLevel::High);
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

#[test]
fn test_field_sanitize_policy_replacement_clears_explicit_exclusions() {
    let mut policy = FieldSanitizePolicy::default();
    policy.exclude_sensitive_field("password");

    let mut replacement = SensitiveFields::new();
    replacement.insert("password", SensitivityLevel::Secret);
    let policy = policy.with_sensitive_fields(replacement);
    let sanitizer = FieldSanitizer::new(policy);

    assert_eq!(
        sanitizer.sensitivity_for_name("password", NameMatchMode::Exact),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_field_sanitize_policy_mutations_cancel_matching_exclusions() {
    let mut policy = FieldSanitizePolicy::default();

    assert_eq!(
        policy.exclude_sensitive_field("API_KEY"),
        Some(SensitivityLevel::High),
    );
    assert!(policy.is_sensitive_field_excluded("api_key"));
    assert_eq!(
        policy.excluded_sensitive_fields().collect::<Vec<_>>(),
        vec!["apikey"],
    );

    policy.insert_sensitive_field("apiKey", SensitivityLevel::Low);
    assert_eq!(
        policy.sensitive_fields().level_for("api_key"),
        Some(SensitivityLevel::Low),
    );
    assert!(!policy.is_sensitive_field_excluded("api_key"));

    policy.exclude_sensitive_field("api_key");
    policy.set_sensitive_field_level("api_key", SensitivityLevel::Medium);
    assert_eq!(
        policy.sensitive_fields().level_for("api_key"),
        Some(SensitivityLevel::Medium),
    );
    assert!(!policy.is_sensitive_field_excluded("api_key"));

    policy.exclude_sensitive_field("password");
    policy.extend_sensitive_fields(["password"], SensitivityLevel::High);
    assert_eq!(
        policy.sensitive_fields().level_for("password"),
        Some(SensitivityLevel::High),
    );
    assert!(!policy.is_sensitive_field_excluded("password"));

    policy.exclude_sensitive_field("password");
    policy.extend_preset(SensitiveFieldPreset::Credentials);
    assert_eq!(
        policy.sensitive_fields().level_for("password"),
        Some(SensitivityLevel::Secret),
    );
    assert!(!policy.is_sensitive_field_excluded("password"));
}

#[test]
fn test_field_sanitize_policy_set_sensitive_fields_clears_all_exclusions() {
    let mut policy = FieldSanitizePolicy::default();
    policy.exclude_sensitive_field("password");
    policy.exclude_sensitive_field("api_key");

    let mut replacement = SensitiveFields::new();
    replacement.insert("custom", SensitivityLevel::High);
    policy.set_sensitive_fields(replacement);

    assert_eq!(
        policy.sensitive_fields().level_for("custom"),
        Some(SensitivityLevel::High),
    );
    assert_eq!(policy.excluded_sensitive_fields().next(), None);
}
