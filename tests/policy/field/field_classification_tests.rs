// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for observable field-classification metadata.

use qubit_redact::FieldClassification;
use qubit_redact::FieldMatchKind;
use qubit_redact::FieldNameMatching;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
/// Verifies sensitive classifications expose their matched rule metadata.
#[test]
fn test_field_classification_exposes_sensitive_rule_metadata() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .matching(FieldNameMatching::ExactOrTokenSuffix)
                .raise("api_token", Sensitivity::High);
        })
        .expect("the field configuration must be valid")
        .build()
        .expect("the configured policy must be valid");

    let classification = policy.classify_field("service_api_token");

    assert_eq!(classification.sensitivity(), Some(Sensitivity::High));
    assert_eq!(classification.matched_field(), Some("apitoken"));
    assert_eq!(classification.match_kind(), Some(FieldMatchKind::TokenSuffix));
    assert!(!classification.is_allowed());
    assert!(!classification.is_unknown());
}

/// Verifies allowed and unknown classifications expose no sensitive metadata.
#[test]
fn test_field_classification_distinguishes_allowed_and_unknown_metadata() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor().allow_exact("display_name");
        })
        .expect("the field configuration must be valid")
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

/// Verifies classification accessors retain the explicit rule selected at the
/// exact-match boundary, including the no-sensitivity allow result.
#[test]
fn test_field_classification_exact_allowed_rule_has_no_sensitivity() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .matching(FieldNameMatching::Exact)
                .raise("request_id", Sensitivity::High)
                .allow_exact("request_id");
        })
        .expect("the field configuration must be valid")
        .build()
        .expect("the configured policy must be valid");

    let classification = policy.classify_field("request_id");
    assert!(classification.is_allowed());
    assert_eq!(classification.sensitivity(), None);
    assert_eq!(classification.matched_field(), Some("requestid"));
    assert_eq!(classification.match_kind(), Some(FieldMatchKind::Exact));
}

/// Verifies the classification predicate methods preserve their distinct
/// allowed and unknown meanings when invoked through their public API.
#[test]
fn test_field_classification_predicates_distinguish_allowed_and_unknown() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor().allow_exact("public_id");
        })
        .expect("the field configuration must be valid")
        .build()
        .expect("the configured policy must be valid");

    let allowed = policy.classify_field("public_id");
    let unknown = policy.classify_field("other");
    let is_allowed = FieldClassification::is_allowed;
    let is_unknown = FieldClassification::is_unknown;

    assert!(is_allowed(allowed));
    assert!(!is_unknown(allowed));
    assert!(!is_allowed(unknown));
    assert!(is_unknown(unknown));
}
