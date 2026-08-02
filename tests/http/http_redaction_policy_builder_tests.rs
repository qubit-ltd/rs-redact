// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`HttpRedactionPolicyBuilder`](qubit_redact::http::HttpRedactionPolicyBuilder).

use qubit_redact::{
    PolicyError,
    PolicyLocation,
    RedactionFloor,
    RedactionFloorState,
    RedactionPolicy,
    Sensitivity,
    http::{
        BodyBudget,
        DiagnosticBudget,
        HttpFieldContext,
        HttpRedactionPolicy,
        JsonDepthBudget,
    },
};

/// Verifies an empty builder owns independently configurable rule snapshots.
#[test]
fn test_builder_uses_three_rule_snapshots() {
    let policy = HttpRedactionPolicy::builder()
        .disable_all_floors()
        .raise(HttpFieldContext::Header, "header-secret", Sensitivity::High)
        .raise(HttpFieldContext::Query, "query-secret", Sensitivity::Secret)
        .raise(HttpFieldContext::Body, "body-secret", Sensitivity::Medium)
        .build()
        .expect("the HTTP policy should be valid");

    assert_eq!(
        policy.header_rules().sensitivity_for("header-secret"),
        Some(Sensitivity::High)
    );
    assert_eq!(
        policy.query_rules().sensitivity_for("query-secret"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        policy.body_rules().sensitivity_for("body-secret"),
        Some(Sensitivity::Medium)
    );
}

/// Verifies shared HTTP masking errors report their own policy location.
#[test]
fn test_shared_mask_validation_reports_http_masking_location() {
    let result = HttpRedactionPolicy::builder()
        .mask(Sensitivity::Secret, qubit_redact::MaskPolicy::fixed(""))
        .build();

    assert_eq!(
        result,
        Err(PolicyError::EmptyFixedReplacement {
            location: PolicyLocation::HttpMasking,
            level: Sensitivity::Secret,
        })
    );
}

/// Verifies context validation errors identify their source.
#[test]
fn test_build_reports_context_policy_location() {
    assert_eq!(
        HttpRedactionPolicy::builder()
            .raise(HttpFieldContext::Header, "---", Sensitivity::High)
            .build(),
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::HttpHeader
        }),
    );
    assert_eq!(
        HttpRedactionPolicy::builder()
            .raise(HttpFieldContext::Query, "---", Sensitivity::High)
            .build(),
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::HttpQuery
        }),
    );
    assert_eq!(
        HttpRedactionPolicy::builder()
            .raise(HttpFieldContext::Body, "---", Sensitivity::High)
            .build(),
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::HttpBody
        }),
    );
}

/// Verifies global and context-specific floor calls are last-call-wins.
#[test]
fn test_floor_configuration_is_independent_and_last_call_wins() {
    let shared_floor = RedactionFloor::builder()
        .raise("shared-floor-secret", Sensitivity::Secret)
        .build()
        .expect("the floor should be valid");
    let policy = HttpRedactionPolicy::builder()
        .floor_all(shared_floor.clone())
        .disable_floor_for(HttpFieldContext::Query)
        .floor_for(HttpFieldContext::Body, shared_floor)
        .disable_floor_for(HttpFieldContext::Body)
        .build()
        .expect("the HTTP policy should be valid");

    assert_eq!(
        policy.header_rules().floor_state(),
        RedactionFloorState::Explicit
    );
    assert_eq!(
        policy.query_rules().floor_state(),
        RedactionFloorState::Disabled
    );
    assert_eq!(
        policy.body_rules().floor_state(),
        RedactionFloorState::Disabled
    );

    let header_floor = RedactionFloor::builder()
        .raise("header-floor-secret", Sensitivity::High)
        .build()
        .expect("the header floor should be valid");
    let global_floor = RedactionFloor::builder()
        .raise("global-floor-secret", Sensitivity::Secret)
        .build()
        .expect("the global floor should be valid");
    let global_last = HttpRedactionPolicy::builder()
        .floor_for(HttpFieldContext::Header, header_floor)
        .disable_floor_for(HttpFieldContext::Query)
        .floor_all(global_floor)
        .build()
        .expect("the global-last HTTP policy should be valid");

    for rules in [
        global_last.header_rules(),
        global_last.query_rules(),
        global_last.body_rules(),
    ] {
        assert_eq!(rules.floor_state(), RedactionFloorState::Explicit);
        assert_eq!(
            rules.sensitivity_for("global-floor-secret"),
            Some(Sensitivity::Secret),
        );
        assert_eq!(rules.sensitivity_for("header-floor-secret"), None);
    }
}

/// Verifies replacement rules and resource budgets copy without coupling.
#[test]
fn test_builder_from_policy_preserves_rules_and_independent_budgets() {
    let base = RedactionPolicy::builder()
        .raise("base-secret", Sensitivity::Secret)
        .build()
        .expect("the policy should be valid");
    let diagnostic_budget =
        DiagnosticBudget::new(128, 256).expect("valid diagnostic budget");
    let body_budget = BodyBudget::new(64, 128).expect("valid body budget");
    let json_depth_budget =
        JsonDepthBudget::new(7).expect("valid JSON depth budget");
    let policy = HttpRedactionPolicy::builder_from(&base)
        .diagnostic_budget(diagnostic_budget)
        .body_budget(body_budget)
        .json_depth_budget(json_depth_budget)
        .build()
        .expect("the HTTP policy should be valid");
    let rebuilt = HttpRedactionPolicy::default()
        .to_builder()
        .build()
        .expect("the default HTTP policy should be valid");

    assert_eq!(policy.header_rules(), base.rules());
    assert_eq!(policy.query_rules(), base.rules());
    assert_eq!(policy.body_rules(), base.rules());
    assert_eq!(policy.diagnostic_budget(), diagnostic_budget);
    assert_eq!(policy.body_budget(), body_budget);
    assert_eq!(policy.json_depth_budget(), json_depth_budget);
    assert_eq!(rebuilt, HttpRedactionPolicy::default());
}
