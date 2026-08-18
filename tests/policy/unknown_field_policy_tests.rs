// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for unknown-field fallback policy behavior.

use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::UnknownFieldPolicy;
/// Verifies the default policy leaves unclassified fields visible.
#[test]
fn test_unknown_field_policy_defaults_to_pass_through() {
    let policy = RedactionPolicy::builder()
        .build()
        .expect("the empty policy should build");

    assert_eq!(policy.unknown_field_policy(), UnknownFieldPolicy::PassThrough,);
    assert_eq!(policy.sensitivity_for("new_field"), None);
    assert!(policy.classify_field("new_field").is_unknown());
}

/// Verifies an explicit fallback redacts unknown fields without altering raw
/// classification or explicit allow and sensitive rules.
#[test]
fn test_unknown_field_policy_applies_after_explicit_rules() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .edit_fields()
            .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::High));
        builder
            .edit_fields()
            .raise("configured", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .allow_exact("public")
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the fallback policy should build");

    assert_eq!(policy.sensitivity_for("new_field"), Some(Sensitivity::High),);
    assert_eq!(policy.sensitivity_for("configured"), Some(Sensitivity::Secret),);
    assert_eq!(policy.sensitivity_for("public"), None);
    assert!(policy.classify_field("new_field").is_unknown());
}

/// Verifies policy copies retain the configured unknown-field fallback.
#[test]
fn test_unknown_field_policy_is_preserved_by_builder_from() {
    let base = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .edit_fields()
            .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Medium));
        builder
    })
    .build()
    .expect("the base policy should build");
    let copied = base.to_builder().build().expect("the copied policy should build");

    assert_eq!(
        copied.unknown_field_policy(),
        UnknownFieldPolicy::Redact(Sensitivity::Medium),
    );
    assert_eq!(copied.sensitivity_for("unconfigured"), Some(Sensitivity::Medium),);
}
