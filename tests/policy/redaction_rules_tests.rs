// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable redaction rule behavior.

use qubit_redact::{
    FieldClassification, FieldMatchKind, FieldNameMatching, RedactionPolicy, Sensitivity,
    UnknownFieldPolicy,
};

/// Verifies exact allow rules win only for exact candidates before suffix
/// rules.
#[test]
fn test_redaction_rules_exact_allow_does_not_hide_suffix_sensitive_rule() {
    let policy = RedactionPolicy::empty_builder()
        .raise("access_token", Sensitivity::High)
        .allow_canonical_exact("access_token")
        .matching(FieldNameMatching::ExactOrTokenSuffix)
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
    let policy = RedactionPolicy::empty_builder()
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Low))
        .build()
        .expect("the fallback policy should be valid");

    assert_eq!(
        policy.sensitivity_for("unconfigured"),
        Some(Sensitivity::Low)
    );
}
