// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`HttpRedactionPolicy`](qubit_redact::http::HttpRedactionPolicy).

use qubit_redact::http::{DiagnosticBudget, HttpFieldContext, HttpRedactionPolicy};
use qubit_redact::{RedactionFloor, Sensitivity};

/// Verifies the default HTTP policy has a non-zero body input budget.
#[test]
fn test_http_redaction_policy_default_has_input_budget() {
    let policy = HttpRedactionPolicy::default();

    assert!(policy.body_budget().max_input_bytes() > 0);
    assert_eq!(policy.diagnostic_budget(), DiagnosticBudget::default());
}

/// Verifies the strict preset applies the unknown-field fallback to all HTTP
/// field contexts while retaining conservative body handling.
#[test]
fn test_http_redaction_policy_strict_preset_redacts_unknown_fields() {
    let policy = HttpRedactionPolicy::strict();

    for rules in [
        policy.header_rules(),
        policy.query_rules(),
        policy.body_rules(),
    ] {
        assert_eq!(
            rules.unknown_field_policy(),
            qubit_redact::UnknownFieldPolicy::Redact(Sensitivity::Secret),
        );
    }
    assert_eq!(
        policy.text_body_policy(),
        qubit_redact::http::TextBodyPolicy::Redact,
    );
    assert_eq!(
        policy.unkeyed_json_value_policy(),
        qubit_redact::http::UnkeyedJsonValuePolicy::Redact,
    );
}

/// Verifies each HTTP field context owns only rules and can independently
/// replace the inherited floor snapshot.
#[test]
fn test_http_redaction_policy_exposes_independent_context_rules_and_floors() {
    let floor = RedactionFloor::builder()
        .raise("floor-secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should be valid");
    let policy = HttpRedactionPolicy::builder()
        .floor_for(HttpFieldContext::Header, floor)
        .disable_floor_for(HttpFieldContext::Query)
        .disable_floor_for(HttpFieldContext::Body)
        .raise(HttpFieldContext::Body, "body-secret", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the HTTP policy should be valid");

    assert_eq!(
        policy.body_rules().sensitivity_for("body-secret"),
        Some(Sensitivity::High)
    );
}
