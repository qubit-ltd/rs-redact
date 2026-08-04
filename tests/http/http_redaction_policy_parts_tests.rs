// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for complete HTTP policy assembly.

use qubit_redact::{
    RedactionPolicy,
    Sensitivity,
    http::HttpFieldContext,
};

/// Verifies complete HTTP policy assembly retains independent context rules.
#[test]
fn test_http_policy_parts_keep_context_rules_independent() {
    let policy = RedactionPolicy::default()
        .to_builder()
        .http_raise(HttpFieldContext::Header, "x-api-key", Sensitivity::Secret)
        .expect("the header rule must be valid")
        .http_raise(HttpFieldContext::Query, "access_token", Sensitivity::High)
        .expect("the query rule must be valid")
        .build()
        .expect("the configured policy must be valid");

    assert_eq!(
        policy.http().header_rules().sensitivity_for("x_api_key"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        policy.http().query_rules().sensitivity_for("access_token"),
        Some(Sensitivity::High)
    );
    assert_eq!(
        policy.http().body_rules().sensitivity_for("access_token"),
        None
    );
}
