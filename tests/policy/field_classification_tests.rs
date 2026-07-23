// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`FieldClassification`](qubit_redact::FieldClassification).

use qubit_redact::{
    FieldClassification,
    FieldNameMatching,
    RedactionPolicy,
    Sensitivity,
};

/// Verifies exact and suffix-sensitive results expose their matched rule.
#[test]
fn test_field_classification_explains_sensitive_matches() {
    let policy = std::hint::black_box(
        RedactionPolicy::empty_builder()
            .raise("token", Sensitivity::Secret)
            .raise("access_token", Sensitivity::Medium)
            .build()
            .expect("the sensitivity policy should be valid"),
    );

    let exact = std::hint::black_box(policy.classify_field("access_token"));
    assert_eq!(exact.sensitivity(), Some(Sensitivity::Medium));
    assert_eq!(exact.matched_field(), Some("accesstoken"));
    assert_eq!(exact.matching(), Some(FieldNameMatching::Exact));
    assert!(!exact.is_allowed());
    assert!(!exact.is_unknown());

    let suffix =
        std::hint::black_box(policy.classify_field("OPENAI_ACCESS_TOKEN"));
    assert_eq!(suffix.sensitivity(), Some(Sensitivity::Medium));
    assert_eq!(suffix.matched_field(), Some("accesstoken"));
    assert_eq!(
        suffix.matching(),
        Some(FieldNameMatching::ExactOrTokenSuffix),
    );
}

/// Verifies allow precedence and the most specific allow explanation.
#[test]
fn test_field_classification_explains_allow_precedence() {
    let policy = std::hint::black_box(
        RedactionPolicy::empty_builder()
            .raise("access_token", Sensitivity::Secret)
            .allow_exact("access_token")
            .allow_suffix("access_token")
            .build()
            .expect("the conflicting policy should be valid"),
    );

    let exact = std::hint::black_box(policy.classify_field("access_token"));
    assert_eq!(exact.sensitivity(), None);
    assert_eq!(exact.matched_field(), Some("accesstoken"));
    assert_eq!(exact.matching(), Some(FieldNameMatching::Exact));
    assert!(exact.is_allowed());
    assert!(!exact.is_unknown());

    let suffix =
        std::hint::black_box(policy.classify_field("OPENAI_ACCESS_TOKEN"));
    assert_eq!(suffix.sensitivity(), None);
    assert_eq!(suffix.matched_field(), Some("accesstoken"));
    assert_eq!(
        suffix.matching(),
        Some(FieldNameMatching::ExactOrTokenSuffix),
    );
    assert!(suffix.is_allowed());
}

/// Verifies unknown and empty names expose no invented rule metadata.
#[test]
fn test_field_classification_reports_unknown_fields() {
    let policy = std::hint::black_box(
        RedactionPolicy::empty_builder()
            .build()
            .expect("the empty policy should be valid"),
    );

    for field in ["", " _-.[ ] ", "ordinary"] {
        let classification = std::hint::black_box(policy.classify_field(field));
        assert_eq!(classification, FieldClassification::Unknown);
        assert_eq!(classification.sensitivity(), None);
        assert_eq!(classification.matched_field(), None);
        assert_eq!(classification.matching(), None);
        assert!(!classification.is_allowed());
        assert!(classification.is_unknown());
    }
}

/// Verifies explainable classification remains behaviorally identical to the
/// established sensitivity lookup.
#[test]
fn test_field_classification_matches_sensitivity_for() {
    let policy = RedactionPolicy::empty_builder()
        .raise("token", Sensitivity::Secret)
        .raise("access_token", Sensitivity::Medium)
        .raise("tenant_secret", Sensitivity::High)
        .allow_exact("tenant_secret")
        .allow_suffix("public_token")
        .build()
        .expect("the parity policy should be valid");

    for field in [
        "",
        "ordinary",
        "token",
        "access_token",
        "OPENAI_ACCESS_TOKEN",
        "tenant_secret",
        "prefix_tenant_secret",
        "public_token",
        "prefix_public_token",
    ] {
        assert_eq!(
            policy.sensitivity_for(field),
            policy.classify_field(field).sensitivity(),
            "classification parity failed for {field:?}",
        );
    }
}
