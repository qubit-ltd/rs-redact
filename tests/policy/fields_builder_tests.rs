// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public application-field builder view.

use qubit_redact::FieldNameMatching;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::UnknownFieldPolicy;

/// Confirms matching, fallback sensitivity, and allow-rule removal are
/// reflected by the built immutable policy.
#[test]
fn test_field_builder_applies_matching_fallback_sensitivity_and_allow_removal() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .matching(FieldNameMatching::ExactOrTokenSuffix)
                .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Low))
                .medium_sensitive("session")
                .high_sensitive("credential")
                .allow_exact("session")
                .clear_allow_rules();
        })
        .expect("field rules should remain valid")
        .build()
        .expect("the policy should build");

    assert_eq!(policy.matching(), FieldNameMatching::ExactOrTokenSuffix);
    assert_eq!(
        policy.unknown_field_policy(),
        UnknownFieldPolicy::Redact(Sensitivity::Low)
    );
    assert_eq!(policy.sensitivity_for("session"), Some(Sensitivity::Medium));
    assert_eq!(policy.sensitivity_for("request_session"), Some(Sensitivity::Medium));
    assert_eq!(policy.sensitivity_for("credential"), Some(Sensitivity::High));
    assert_eq!(policy.sensitivity_for("unclassified"), Some(Sensitivity::Low));
    assert!(policy.application_allow_rules().next().is_none());
}
