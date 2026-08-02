// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable redaction policies and rule matching.

use proptest::{
    prop_assert_eq,
    proptest,
};
use qubit_redact::{
    FieldNameMatching,
    MaskPolicy,
    PolicyError,
    PolicyLocation,
    RedactionPolicy,
    RedactionPolicyBuilder,
    SensitiveFieldPreset,
    Sensitivity,
};

/// Verifies that an exact allow rule does not allow a contextual suffix.
#[test]
fn test_exact_allow_does_not_allow_contextual_suffix() {
    let policy = RedactionPolicy::builder()
        .disable_floor()
        .raise("access_token", Sensitivity::High)
        .allow_canonical_exact("access_token")
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
    let policy = RedactionPolicy::builder()
        .disable_floor()
        .allow_suffix("access_token")
        .build()
        .expect("the suffix allow rule should be valid");

    assert_eq!(policy.sensitivity_for("access_token"), None);
    assert_eq!(policy.sensitivity_for("OPENAI_ACCESS_TOKEN"), None);
}

/// Verifies that a longer candidate wins before its shorter token suffix.
#[test]
fn test_longest_rule_wins_before_shorter_token() {
    let policy = RedactionPolicy::builder()
        .disable_floor()
        .override_level("token", Sensitivity::Secret)
        .override_level("access_token", Sensitivity::Medium)
        .matching(FieldNameMatching::ExactOrTokenSuffix)
        .build()
        .expect("the sensitivity rules should be valid");

    assert_eq!(
        policy.sensitivity_for("OPENAI_ACCESS_TOKEN"),
        Some(Sensitivity::Medium),
    );
}

/// Verifies that exact matching does not silently use token-suffix lookup.
#[test]
fn test_matching_exact_only_matches_complete_field_name() {
    let policy = RedactionPolicy::builder()
        .disable_floor()
        .raise("access_token", Sensitivity::High)
        .matching(FieldNameMatching::Exact)
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
        qubit_redact::UnknownFieldPolicy::Redact(Sensitivity::Secret),
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
    let builder = RedactionPolicy::builder()
        .raise("tenant_id", Sensitivity::Low)
        .build()
        .expect("the empty policy should be valid");
    let constructed = RedactionPolicyBuilder::new()
        .raise("tenant_id", Sensitivity::Low)
        .build()
        .expect("the constructed empty policy should be valid");
    let defaulted = RedactionPolicyBuilder::default()
        .raise("tenant_id", Sensitivity::Low)
        .build()
        .expect("the default empty policy should be valid");
    let from_default = RedactionPolicy::default()
        .to_builder()
        .raise("tenant_id", Sensitivity::Low)
        .build()
        .expect("the default-based policy should be valid");
    let copied = RedactionPolicy::builder_from(&from_default)
        .include_preset(SensitiveFieldPreset::Session)
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
    let base = RedactionPolicy::builder()
        .disable_floor()
        .matching(FieldNameMatching::Exact)
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[copied]"))
        .raise("tenant_secret", Sensitivity::Secret)
        .raise("public_token", Sensitivity::High)
        .raise("diagnostic_token", Sensitivity::Medium)
        .allow_canonical_exact("public_token")
        .allow_suffix("diagnostic_token")
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
    let policy = RedactionPolicy::builder()
        .disable_floor()
        .raise("credential", Sensitivity::High)
        .raise("credential", Sensitivity::Medium)
        .override_level("override", Sensitivity::High)
        .override_level("override", Sensitivity::Low)
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
    let policy = RedactionPolicy::builder()
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[hidden]"))
        .build()
        .expect("the mask policy should be valid");

    assert_eq!(
        policy.masking().mask(Sensitivity::Secret, "value"),
        "[hidden]"
    );
    assert_eq!(policy.masking().mask(Sensitivity::High, "value"), "****");
}

/// Verifies that empty canonical field names are rejected consistently.
#[test]
fn test_build_rejects_empty_canonical_field_names() {
    for result in [
        RedactionPolicy::builder()
            .raise(" _-.[ ] ", Sensitivity::High)
            .build(),
        RedactionPolicy::builder()
            .override_level(" _-.[ ] ", Sensitivity::High)
            .build(),
        RedactionPolicy::builder()
            .allow_canonical_exact(" _-.[ ] ")
            .build(),
        RedactionPolicy::builder().allow_suffix(" _-.[ ] ").build(),
    ] {
        assert_eq!(
            result,
            Err(PolicyError::EmptyFieldName {
                location: PolicyLocation::Rules
            })
        );
    }
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

/// Verifies that fixed masks require a non-empty replacement.
#[test]
fn test_build_rejects_empty_fixed_replacement() {
    let result = RedactionPolicy::builder()
        .mask(Sensitivity::High, MaskPolicy::fixed(""))
        .build();

    assert_eq!(
        result,
        Err(PolicyError::EmptyFixedReplacement {
            location: PolicyLocation::Rules,
            level: Sensitivity::High,
        }),
    );

    assert!(
        RedactionPolicy::builder()
            .mask(Sensitivity::High, MaskPolicy::empty())
            .build()
            .is_ok(),
    );
}

/// Verifies empty builders and validation errors expose useful
/// diagnostics.
#[test]
fn test_builder_and_policy_error_display() {
    let policy = RedactionPolicy::builder()
        .disable_floor()
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
    let policy = RedactionPolicy::builder()
        .raise("Tenant-Token", Sensitivity::High)
        .allow_canonical_exact("Public Token")
        .allow_suffix("Diagnostic.Token")
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
