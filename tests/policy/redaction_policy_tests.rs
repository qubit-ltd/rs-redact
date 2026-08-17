// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable redaction policies and rule matching.

use proptest::prop_assert_eq;
use proptest::proptest;
use qubit_redact::FieldNameMatching;
use qubit_redact::MaskPolicy;
use qubit_redact::PolicyError;
use qubit_redact::PolicyLocation;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionPolicyBuilder;
use qubit_redact::SensitiveFieldPreset;
use qubit_redact::Sensitivity;
use qubit_redact::UnknownFieldPolicy;
/// Verifies that an exact allow rule does not allow a contextual suffix.
#[test]
fn test_exact_allow_does_not_allow_contextual_suffix() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        builder
            .edit_fields()
            .raise("access_token", Sensitivity::High)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .allow_exact("access_token")
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the exact allow rule should be valid");

    assert_eq!(policy.sensitivity_for("access_token"), None);
    assert_eq!(
        policy.sensitivity_for("OPENAI_ACCESS_TOKEN"),
        Some(Sensitivity::High),
    );
}

/// Verifies that a suffix allow rule explicitly allows contextual suffixes.
#[test]
fn test_suffix_allow_is_explicitly_broad() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        builder
            .edit_fields()
            .allow_suffix("access_token")
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the suffix allow rule should be valid");

    assert_eq!(policy.sensitivity_for("access_token"), None);
    assert_eq!(policy.sensitivity_for("OPENAI_ACCESS_TOKEN"), None);
}

/// Verifies overlapping sensitive rules resolve to the strongest level.
#[test]
fn test_overlapping_sensitive_rules_resolve_to_strongest_level() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        builder
            .edit_fields()
            .override_level("token", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .override_level("access_token", Sensitivity::Medium)
            .expect("the test builder input should be valid");
        let _ = builder
            .edit_fields()
            .matching(FieldNameMatching::ExactOrTokenSuffix);
        builder
    })
    .build()
    .expect("the sensitivity rules should be valid");

    assert_eq!(
        policy.sensitivity_for("OPENAI_ACCESS_TOKEN"),
        Some(Sensitivity::Secret),
    );
}

/// Verifies that exact matching does not silently use token-suffix lookup.
#[test]
fn test_matching_exact_only_matches_complete_field_name() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        builder
            .edit_fields()
            .raise("access_token", Sensitivity::High)
            .expect("the test builder input should be valid");
        let _ = builder.edit_fields().matching(FieldNameMatching::Exact);
        builder
    })
    .build()
    .expect("the exact-matching policy should be valid");

    assert_eq!(
        policy.sensitivity_for("access_token"),
        Some(Sensitivity::High),
    );
    assert_eq!(policy.sensitivity_for("OPENAI_ACCESS_TOKEN"), None);
}

/// Verifies that the standard and default policies contain built-in rules.
#[test]
fn test_standard_and_default_contain_presets_and_extra_fields() {
    for policy in [RedactionPolicy::standard(), RedactionPolicy::default()] {
        assert_eq!(
            policy.sensitivity_for("password"),
            Some(Sensitivity::Secret),
        );
        assert_eq!(
            policy.sensitivity_for("OPENAI_API_KEY"),
            Some(Sensitivity::High),
        );
        assert_eq!(
            policy.sensitivity_for("database_url"),
            Some(Sensitivity::Secret),
        );
        assert_eq!(policy.matching(), FieldNameMatching::ExactOrTokenSuffix,);
    }
}

/// Verifies the strict preset redacts unknown application fields.
#[test]
fn test_strict_preset_redacts_unknown_fields() {
    let policy = RedactionPolicy::strict();

    assert_eq!(
        policy.unknown_field_policy(),
        UnknownFieldPolicy::Redact(Sensitivity::Secret),
    );
    assert_eq!(
        policy.sensitivity_for("custom_field"),
        Some(Sensitivity::Secret)
    );
}

/// Verifies that ordinary builders have empty application rules and the
/// standard floor.
#[test]
fn test_builder_is_empty_and_default_based_builder_is_explicit() {
    let builder = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .edit_fields()
            .raise("tenant_id", Sensitivity::Low)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the empty policy should be valid");
    let constructed = ({
        let mut builder = RedactionPolicyBuilder::new();
        builder
            .edit_fields()
            .raise("tenant_id", Sensitivity::Low)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the constructed empty policy should be valid");
    let defaulted = ({
        let mut builder = RedactionPolicyBuilder::default();
        builder
            .edit_fields()
            .raise("tenant_id", Sensitivity::Low)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the default empty policy should be valid");
    let from_default = ({
        let mut builder = RedactionPolicy::default().to_builder();
        builder
            .edit_fields()
            .raise("tenant_id", Sensitivity::Low)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the default-based policy should be valid");
    let copied = ({
        let mut builder = RedactionPolicy::builder_from(&from_default);
        builder
            .edit_fields()
            .include_preset(SensitiveFieldPreset::Session);
        builder
    })
    .build()
    .expect("the copied policy should be valid");

    assert_eq!(
        builder.sensitivity_for("password"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        builder
            .application_sensitive_rules()
            .map(|rule| (rule.field(), rule.sensitivity()))
            .collect::<Vec<_>>(),
        vec![("tenantid", Sensitivity::Low)],
    );
    assert_eq!(constructed, builder);
    assert_eq!(defaulted, builder);
    assert_eq!(
        from_default.sensitivity_for("password"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        copied.sensitivity_for("session_token"),
        Some(Sensitivity::High),
    );
    assert_eq!(
        copied.sensitivity_for("password"),
        Some(Sensitivity::Secret)
    );
}

/// Verifies that copying the current snapshot replaces every prior builder
/// state.
#[test]
fn test_builder_from_snapshot_replaces_existing_state_and_error() {
    let policy = RedactionPolicy::default().to_builder().build().expect(
        "the complete default replacement should clear the prior error",
    );

    assert_eq!(policy, RedactionPolicy::default());
    assert_eq!(policy.sensitivity_for("custom_only"), None);
}

/// Verifies that `builder_from` copies every observable policy component.
#[test]
fn test_builder_from_copies_complete_policy_snapshot() {
    let base = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        let _ = builder.edit_fields().matching(FieldNameMatching::Exact);
        builder
            .edit_fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[copied]"))
            .expect("the test mask policy should be valid");
        builder
            .edit_fields()
            .raise("tenant_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .raise("public_token", Sensitivity::High)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .raise("diagnostic_token", Sensitivity::Medium)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .allow_exact("public_token")
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .allow_suffix("diagnostic_token")
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the complete base policy should be valid");
    let copied = RedactionPolicy::builder_from(&base)
        .build()
        .expect("the copied policy should remain valid");
    let sensitive = copied.application_sensitive_rules().collect::<Vec<_>>();
    let allowed = copied.application_allow_rules().collect::<Vec<_>>();

    assert_eq!(copied.matching(), FieldNameMatching::Exact);
    assert_eq!(
        copied.masking().mask(Sensitivity::Secret, "secret"),
        "[copied]",
    );
    assert_eq!(
        copied.sensitivity_for("tenant_secret"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(copied.sensitivity_for("OPENAI_TENANT_SECRET"), None);
    assert_eq!(copied.sensitivity_for("public_token"), None);
    assert_eq!(copied.sensitivity_for("diagnostic_token"), None);
    assert!(sensitive.iter().any(|rule| {
        rule.field() == "publictoken" && rule.sensitivity() == Sensitivity::High
    }));
    assert!(sensitive.iter().any(|rule| {
        rule.field() == "diagnostictoken"
            && rule.sensitivity() == Sensitivity::Medium
    }));
    assert!(allowed.iter().any(|rule| {
        rule.field() == "publictoken"
            && rule.matching() == FieldNameMatching::Exact
    }));
    assert!(allowed.iter().any(|rule| {
        rule.field() == "diagnostictoken"
            && rule.matching() == FieldNameMatching::ExactOrTokenSuffix
    }));
}

/// Verifies that raising never weakens a rule while overriding replaces it.
#[test]
fn test_raise_and_override_have_distinct_strength_semantics() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        builder
            .edit_fields()
            .raise("credential", Sensitivity::High)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .raise("credential", Sensitivity::Medium)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .override_level("override", Sensitivity::High)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .override_level("override", Sensitivity::Low)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the sensitivity rules should be valid");

    assert_eq!(
        policy.sensitivity_for("credential"),
        Some(Sensitivity::High),
    );
    assert_eq!(policy.sensitivity_for("override"), Some(Sensitivity::Low),);
}

/// Verifies that masking can be replaced and queried by sensitivity level.
#[test]
fn test_mask_replaces_one_masking_policy() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .edit_fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[hidden]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the mask policy should be valid");

    assert_eq!(
        policy.masking().mask(Sensitivity::Secret, "value"),
        "[hidden]"
    );
    assert_eq!(policy.masking().mask(Sensitivity::High, "value"), "****");
}

/// Verifies that empty canonical field names are rejected immediately.
#[test]
fn test_setters_reject_empty_canonical_field_names() {
    let expected = Some(PolicyError::EmptyFieldName {
        location: PolicyLocation::Rules,
    });
    let mut builder = RedactionPolicy::builder();
    assert_eq!(
        builder
            .edit_fields()
            .raise(" _-.[ ] ", Sensitivity::High)
            .err(),
        expected,
    );
    assert_eq!(
        builder
            .edit_fields()
            .override_level(" _-.[ ] ", Sensitivity::High)
            .err(),
        expected,
    );
    assert_eq!(
        builder.edit_fields().allow_exact(" _-.[ ] ").err(),
        expected,
    );
    assert_eq!(
        builder.edit_fields().allow_suffix(" _-.[ ] ").err(),
        expected,
    );
}

/// Verifies direct field-name validation matches builder canonicalization.
#[test]
fn test_validate_field_name_accepts_canonicalizable_names_and_rejects_empty() {
    assert_eq!(
        RedactionPolicyBuilder::validate_field_name("Tenant-Token"),
        Ok(()),
    );
    assert_eq!(
        RedactionPolicyBuilder::validate_field_name(" _-.[ ] "),
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules
        }),
    );
}

/// Verifies that fixed masks require a non-empty replacement immediately.
#[test]
fn test_mask_rejects_empty_fixed_replacement_immediately() {
    let mut builder = RedactionPolicy::builder();
    let error = builder
        .edit_fields()
        .mask(Sensitivity::High, MaskPolicy::fixed(""))
        .err();

    assert_eq!(
        error,
        Some(PolicyError::EmptyFixedReplacement {
            location: PolicyLocation::Rules,
            level: Sensitivity::High,
        }),
    );

    assert!(
        ({
            let mut builder = RedactionPolicy::builder();
            builder
                .edit_fields()
                .mask(Sensitivity::High, MaskPolicy::empty())
                .expect("the test mask policy should be valid");
            builder
        })
        .build()
        .is_ok(),
    );
}

/// Verifies empty builders and validation errors expose useful
/// diagnostics.
#[test]
fn test_builder_and_policy_error_display() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        builder
    })
    .build()
    .expect("the builder should be valid");
    assert_eq!(policy.sensitivity_for("password"), None);
    assert_eq!(
        PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules
        }
        .to_string(),
        "field name is empty after canonicalization in rules",
    );
    assert_eq!(
        PolicyError::EmptyFixedReplacement {
            location: PolicyLocation::Rules,
            level: Sensitivity::Medium,
        }
        .to_string(),
        "fixed mask replacement for Medium sensitivity is empty in rules",
    );
}

/// Verifies that immutable rule views expose canonical, sorted rule data.
#[test]
fn test_rule_views_expose_canonical_configuration() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .edit_fields()
            .raise("Tenant-Token", Sensitivity::High)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .allow_exact("Public Token")
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .allow_suffix("Diagnostic.Token")
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the policy rules should be valid");
    let sensitive = policy.application_sensitive_rules().collect::<Vec<_>>();
    let allowed = policy.application_allow_rules().collect::<Vec<_>>();

    assert_eq!(sensitive.len(), 1);
    assert_eq!(sensitive[0].field(), "tenanttoken");
    assert_eq!(sensitive[0].sensitivity(), Sensitivity::High);
    assert_eq!(allowed.len(), 2);
    assert_eq!(allowed[0].field(), "publictoken");
    assert_eq!(allowed[0].matching(), FieldNameMatching::Exact);
    assert_eq!(allowed[1].field(), "diagnostictoken");
    assert_eq!(allowed[1].matching(), FieldNameMatching::ExactOrTokenSuffix,);
}

proptest! {
    /// Verifies that repeated policy lookup is deterministic for arbitrary names.
    #[test]
    fn test_policy_lookup_is_deterministic(name in ".*") {
        let policy = RedactionPolicy::standard();
        prop_assert_eq!(
            policy.sensitivity_for(&name),
            policy.sensitivity_for(&name),
        );
    }
}
