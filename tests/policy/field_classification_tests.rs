// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for observable field-classification metadata.

use qubit_redact::FieldMatchKind;
use qubit_redact::FieldNameMatching;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
/// Verifies sensitive classifications expose their matched rule metadata.
#[test]
fn test_field_classification_exposes_sensitive_rule_metadata() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().disable_floor();
        builder
            .fields()
            .matching(FieldNameMatching::ExactOrTokenSuffix);
        builder
            .fields()
            .raise("api_token", Sensitivity::High)
            .expect("the configured field must be valid");
        builder
    })
    .build()
    .expect("the configured policy must be valid");

    let classification = policy.classify_field("service_api_token");

    assert_eq!(classification.sensitivity(), Some(Sensitivity::High));
    assert_eq!(classification.matched_field(), Some("apitoken"));
    assert_eq!(
        classification.match_kind(),
        Some(FieldMatchKind::TokenSuffix)
    );
    assert!(!classification.is_allowed());
    assert!(!classification.is_unknown());
}

/// Verifies allowed and unknown classifications expose no sensitive metadata.
#[test]
fn test_field_classification_distinguishes_allowed_and_unknown_metadata() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().disable_floor();
        builder
            .fields()
            .allow_exact("display_name")
            .expect("the configured field must be valid");
        builder
    })
    .build()
    .expect("the configured policy must be valid");

    let allowed = policy.classify_field("display_name");
    assert_eq!(allowed.sensitivity(), None);
    assert_eq!(allowed.matched_field(), Some("displayname"));
    assert_eq!(allowed.match_kind(), Some(FieldMatchKind::Exact));
    assert!(allowed.is_allowed());
    assert!(!allowed.is_unknown());

    let unknown = policy.classify_field("unconfigured_field");
    assert_eq!(unknown.sensitivity(), None);
    assert_eq!(unknown.matched_field(), None);
    assert_eq!(unknown.match_kind(), None);
    assert!(!unknown.is_allowed());
    assert!(unknown.is_unknown());
}
