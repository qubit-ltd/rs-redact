// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`HttpRedactionPolicy`](qubit_redact::http::HttpRedactionPolicy).

use qubit_redact::http::{
    DiagnosticBudget,
    HttpRedactionPolicy,
};
use qubit_redact::{
    RedactionFloor,
    RedactionFloorState,
    Sensitivity,
};

/// Verifies the default HTTP policy has a non-zero body input budget.
#[test]
fn test_http_redaction_policy_default_has_input_budget() {
    let policy = HttpRedactionPolicy::default();

    assert!(policy.body_budget().max_input_bytes() > 0);
    assert_eq!(policy.diagnostic_budget(), DiagnosticBudget::default());
}

/// Verifies each HTTP field context owns only rules and can independently
/// replace the inherited floor snapshot.
#[test]
fn test_http_redaction_policy_exposes_independent_context_rules_and_floors() {
    let floor = RedactionFloor::builder()
        .raise("floor-secret", Sensitivity::Secret)
        .build()
        .expect("the floor should be valid");
    let policy = HttpRedactionPolicy::builder()
        .header_floor(floor)
        .disable_query_floor()
        .disable_body_floor()
        .raise_body("body-secret", Sensitivity::High)
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
        policy.body_rules().sensitivity_for("body-secret"),
        Some(Sensitivity::High)
    );
}
