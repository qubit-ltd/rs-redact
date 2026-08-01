// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for complete HTTP policy construction state.

use qubit_redact::{
    RedactionPolicy,
    Sensitivity,
    http::HttpRedactionPolicy,
};

/// Verifies complete policy construction retains distinct rule snapshots for
/// each HTTP field context.
#[test]
fn test_http_redaction_policy_parts_keep_context_rules_distinct() {
    let header_rules = RedactionPolicy::builder()
        .disable_floor()
        .raise("header_only", Sensitivity::High)
        .build()
        .expect("header rules should be valid")
        .rules()
        .clone();
    let query_rules = RedactionPolicy::builder()
        .disable_floor()
        .raise("query_only", Sensitivity::High)
        .build()
        .expect("query rules should be valid")
        .rules()
        .clone();
    let body_rules = RedactionPolicy::builder()
        .disable_floor()
        .raise("body_only", Sensitivity::High)
        .build()
        .expect("body rules should be valid")
        .rules()
        .clone();
    let policy = HttpRedactionPolicy::builder()
        .header_rules(header_rules)
        .query_rules(query_rules)
        .body_rules(body_rules)
        .build()
        .expect("the complete HTTP policy should be valid");

    assert_eq!(
        policy.header_rules().sensitivity_for("header_only"),
        Some(Sensitivity::High),
    );
    assert_eq!(policy.query_rules().sensitivity_for("header_only"), None);
    assert_eq!(policy.body_rules().sensitivity_for("header_only"), None);
}
