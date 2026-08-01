// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
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
        HttpRedactionPolicy,
        JsonDepthBudget,
    },
};

/// Verifies an empty builder owns independently configurable rule snapshots.
#[test]
fn test_empty_builder_uses_three_rule_snapshots() {
    let policy = HttpRedactionPolicy::empty_builder()
        .disable_floor()
        .raise_header("header-secret", Sensitivity::High)
        .raise_query("query-secret", Sensitivity::Secret)
        .raise_body("body-secret", Sensitivity::Medium)
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

/// Verifies context validation errors identify their source.
#[test]
fn test_build_reports_context_policy_location() {
    assert_eq!(
        HttpRedactionPolicy::empty_builder()
            .raise_header("---", Sensitivity::High)
            .build(),
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::HttpHeader
        }),
    );
    assert_eq!(
        HttpRedactionPolicy::empty_builder()
            .raise_query("---", Sensitivity::High)
            .build(),
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::HttpQuery
        }),
    );
    assert_eq!(
        HttpRedactionPolicy::empty_builder()
            .raise_body("---", Sensitivity::High)
            .build(),
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::HttpBody
        }),
    );
}

/// Verifies global and context-specific floor calls are last-call-wins.
#[test]
fn test_floor_configuration_is_independent_and_last_call_wins() {
    let shared_floor = RedactionFloor::empty_builder()
        .raise("shared-floor-secret", Sensitivity::Secret)
        .build()
        .expect("the floor should be valid");
    let policy = HttpRedactionPolicy::empty_builder()
        .floor(shared_floor.clone())
        .disable_query_floor()
        .body_floor(shared_floor)
        .disable_body_floor()
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

    let header_floor = RedactionFloor::empty_builder()
        .raise("header-floor-secret", Sensitivity::High)
        .build()
        .expect("the header floor should be valid");
    let global_floor = RedactionFloor::empty_builder()
        .raise("global-floor-secret", Sensitivity::Secret)
        .build()
        .expect("the global floor should be valid");
    let global_last = HttpRedactionPolicy::empty_builder()
        .header_floor(header_floor)
        .disable_query_floor()
        .floor(global_floor)
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
    let base = RedactionPolicy::empty_builder()
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
    let rebuilt = HttpRedactionPolicy::builder_from_default()
        .load_default()
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
