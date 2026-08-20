// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`AllowRule`](qubit_redact::AllowRule) views.

use qubit_redact::FieldNameMatching;
use qubit_redact::RedactionPolicy;
/// Verifies an exact allow rule is exposed with its canonical field name.
#[test]
fn test_allow_rule_exposes_exact_field_and_matching_mode() {
    let policy = std::hint::black_box(
        RedactionPolicy::builder()
            .fields(|fields| {
                fields.allow_exact("public-token");
            })
            .expect("the field configuration should be valid")
            .build()
            .expect("the allow rule should be valid"),
    );
    let rule = policy
        .application_allow_rules()
        .next()
        .expect("the configured allow rule should be visible");

    assert_eq!(rule.field(), "publictoken");
    assert_eq!(rule.matching(), FieldNameMatching::Exact);
}

/// Verifies a suffix allow rule exposes its broader matching mode.
#[test]
fn test_allow_rule_exposes_suffix_matching_mode() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.allow_suffix("token");
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the allow rule should be valid");
    let rule = policy
        .application_allow_rules()
        .next()
        .expect("the configured allow rule should be visible");

    assert_eq!(rule.field(), "token");
    assert_eq!(
        std::hint::black_box(rule.matching()),
        FieldNameMatching::ExactOrTokenSuffix,
    );
}
