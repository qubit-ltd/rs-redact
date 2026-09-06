// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable redaction rule behavior.

use qubit_redact::FieldClassification;
use qubit_redact::FieldMatchKind;
use qubit_redact::FieldNameMatching;
use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionRules;
use qubit_redact::Sensitivity;
use qubit_redact::UnknownFieldPolicy;
/// Verifies exact allow rules win only for exact candidates before suffix
/// rules.
#[test]
fn test_redaction_rules_exact_allow_does_not_hide_suffix_sensitive_rule() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .raise("access_token", Sensitivity::High)
                .allow_exact("access_token")
                .matching(FieldNameMatching::ExactOrTokenSuffix);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy rules should be valid");

    assert!(matches!(
        policy.classify_field("access_token"),
        FieldClassification::Allowed {
            match_kind: FieldMatchKind::Exact,
            ..
        }
    ));
    assert!(matches!(
        policy.classify_field("OPENAI_ACCESS_TOKEN"),
        FieldClassification::Sensitive {
            match_kind: FieldMatchKind::TokenSuffix,
            ..
        }
    ));
}

/// Verifies unknown-field fallback sensitivity is applied after rule lookup.
#[test]
fn test_redaction_rules_unknown_field_falls_back_to_policy() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Low));
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the fallback policy should be valid");

    assert_eq!(
        policy.sensitivity_for("unconfigured"),
        Some(Sensitivity::Low)
    );
}

/// Verifies the rule snapshot exposes application-only matching and fallback
/// configuration independently from any floor.
#[test]
fn test_redaction_rules_expose_application_matching_and_unknown_policy() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .matching(FieldNameMatching::Exact)
                .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Low));
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the application rules should be valid");
    let matching: fn(&RedactionRules) -> FieldNameMatching = RedactionRules::matching;
    let unknown_field_policy: fn(&RedactionRules) -> UnknownFieldPolicy =
        RedactionRules::unknown_field_policy;

    assert_eq!(matching(policy.rules()), FieldNameMatching::Exact);
    assert_eq!(
        unknown_field_policy(policy.rules()),
        UnknownFieldPolicy::Redact(Sensitivity::Low),
    );
}

/// Verifies the floor also retains the strongest overlapping sensitive rule.
#[test]
fn test_redaction_rules_floor_resolves_overlaps_to_strongest_level() {
    let floor = RedactionFloor::builder()
        .raise("token", Sensitivity::Secret)
        .expect("the shorter floor rule should be valid")
        .raise("access_token", Sensitivity::Medium)
        .expect("the longer floor rule should be valid")
        .build()
        .expect("the overlapping floor should be valid");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.floor(floor);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should be valid");

    assert_eq!(
        policy.sensitivity_for("OPENAI_ACCESS_TOKEN"),
        Some(Sensitivity::Secret),
    );
}

/// Verifies direct immutable rule edits replace and then remove the floor
/// without mutating the application rule snapshot.
#[test]
fn test_redaction_rules_with_floor_and_disable_floor_are_immutable() {
    let floor = RedactionFloor::builder()
        .raise("floor_only", Sensitivity::High)
        .expect("the test floor field should be valid")
        .build()
        .expect("the test floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .raise("application_only", Sensitivity::Low);
        })
        .expect("the application configuration should be valid")
        .build()
        .expect("the base policy should build");
    let with_floor = policy.rules().clone().with_floor(floor);
    let without_floor = with_floor.clone().disable_floor();

    assert!(policy.rules().floor().is_none());
    assert_eq!(
        with_floor.sensitivity_for("floor_only"),
        Some(Sensitivity::High)
    );
    assert_eq!(
        with_floor.sensitivity_for("application_only"),
        Some(Sensitivity::Low)
    );
    assert_eq!(without_floor.sensitivity_for("floor_only"), None);
    assert_eq!(
        without_floor.sensitivity_for("application_only"),
        Some(Sensitivity::Low)
    );
}

/// Verifies an application allow rule explicitly suppresses its own fallback
/// while retaining the classification information for diagnostics.
#[test]
fn test_redaction_rules_allow_rule_suppresses_unknown_field_fallback() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Secret))
                .allow_suffix("diagnostic");
        })
        .expect("the policy draft should be valid")
        .build()
        .expect("the policy should build");

    assert!(matches!(
        policy.classify_field("request_diagnostic"),
        FieldClassification::Allowed {
            match_kind: FieldMatchKind::TokenSuffix,
            ..
        }
    ));
    assert_eq!(policy.sensitivity_for("request_diagnostic"), None);
    assert_eq!(
        policy.sensitivity_for("other_field"),
        Some(Sensitivity::Secret)
    );
}
