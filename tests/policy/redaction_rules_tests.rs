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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("access_token", Sensitivity::High)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .allow_exact("access_token")
            .expect("the test builder input should be valid");
        let _ = builder
            .fields()
            .matching(FieldNameMatching::ExactOrTokenSuffix);
        builder
    })
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Low));
        builder
    })
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().disable_floor();
        let _ = builder.fields().matching(FieldNameMatching::Exact);
        builder
            .fields()
            .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Low));
        builder
    })
    .build()
    .expect("the application rules should be valid");
    let matching: fn(&RedactionRules) -> FieldNameMatching =
        RedactionRules::matching;
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        let _ = builder.fields().floor(floor);
        builder
    })
    .build()
    .expect("the policy should be valid");

    assert_eq!(
        policy.sensitivity_for("OPENAI_ACCESS_TOKEN"),
        Some(Sensitivity::Secret),
    );
}
