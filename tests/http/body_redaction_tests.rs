// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable HTTP policy and body-result public contracts.

use std::fmt::Display;

use qubit_redact::{
    LogSafeText,
    PolicyError,
    RedactionPolicy,
    Sensitivity,
    http::{
        BodyBudget,
        BodyRedaction,
        BodyRedactionReason,
        BodyRedactionStatus,
        HttpRedactionPolicy,
        HttpRedactionPolicyBuilder,
    },
};

/// Asserts at compile time that a public result implements [`Display`].
fn assert_display<T: Display>() {}

/// Verifies HTTP defaults use independent policy snapshots and hard budgets.
#[test]
fn test_http_redaction_policy_default_uses_safe_values() {
    let policy = HttpRedactionPolicy::default();

    assert_eq!(policy.header_policy(), &RedactionPolicy::default(),);
    assert_eq!(policy.query_policy(), &RedactionPolicy::default());
    assert_eq!(policy.body_policy(), &RedactionPolicy::default());
    assert_eq!(policy.body_budget().max_input_bytes(), 16 * 1024);
    assert_eq!(policy.body_budget().max_output_bytes(), 64 * 1024);
}

/// Verifies the builder default follows the current field-policy default.
#[test]
fn test_http_redaction_policy_builder_default_uses_safe_values() {
    let policy = HttpRedactionPolicyBuilder::default()
        .build()
        .expect("HTTP redaction policy should be valid");

    assert_eq!(policy, HttpRedactionPolicy::default());
}

/// Verifies each HTTP context can receive an independent immutable snapshot.
#[test]
fn test_http_redaction_policy_builder_overrides_each_context() {
    let base = RedactionPolicy::default();
    let header = RedactionPolicy::empty_builder()
        .raise("header_secret", Sensitivity::Secret)
        .build()
        .expect("header policy should be valid");
    let query = RedactionPolicy::empty_builder()
        .raise("query_secret", Sensitivity::Secret)
        .build()
        .expect("query policy should be valid");
    let body = RedactionPolicy::empty_builder()
        .raise("body_secret", Sensitivity::Secret)
        .build()
        .expect("body policy should be valid");
    let budget = BodyBudget::new(32, 48).expect("budget should be valid");

    let policy = HttpRedactionPolicy::builder_from(base)
        .header_policy(header.clone())
        .query_policy(query.clone())
        .body_policy(body.clone())
        .body_budget(budget)
        .build()
        .expect("HTTP redaction policy should be valid");

    assert_eq!(policy.header_policy(), &header);
    assert_eq!(policy.query_policy(), &query);
    assert_eq!(policy.body_policy(), &body);
    assert_eq!(policy.body_budget(), budget);
}

/// Verifies one upstream builder owns independent mutable rules for every
/// HTTP field context.
#[test]
fn test_http_redaction_policy_builder_configures_context_rules() {
    let base = RedactionPolicy::empty_builder()
        .build()
        .expect("empty base policy should be valid");

    let policy = HttpRedactionPolicy::builder_from(base)
        .raise_header("header_secret", Sensitivity::High)
        .override_header("header_secret", Sensitivity::Low)
        .raise_header("visible_header", Sensitivity::Secret)
        .allow_header_exact("visible_header")
        .raise_header("public_header", Sensitivity::Secret)
        .allow_header_suffix("public_header")
        .raise_query("query_secret", Sensitivity::Secret)
        .override_query("query_secret", Sensitivity::Medium)
        .raise_query("visible_query", Sensitivity::Secret)
        .allow_query_exact("visible_query")
        .raise_query("public_query", Sensitivity::Secret)
        .allow_query_suffix("public_query")
        .raise_body("body_secret", Sensitivity::Secret)
        .override_body("body_secret", Sensitivity::High)
        .raise_body("visible_body", Sensitivity::Secret)
        .allow_body_exact("visible_body")
        .raise_body("public_body", Sensitivity::Secret)
        .allow_body_suffix("public_body")
        .build()
        .expect("independent HTTP context rules should be valid");

    assert_eq!(
        policy.header_policy().sensitivity_for("header_secret"),
        Some(Sensitivity::Low),
    );
    assert_eq!(
        policy.query_policy().sensitivity_for("query_secret"),
        Some(Sensitivity::Medium),
    );
    assert_eq!(
        policy.body_policy().sensitivity_for("body_secret"),
        Some(Sensitivity::High),
    );
    assert_eq!(
        policy.header_policy().sensitivity_for("visible_header"),
        None,
    );
    assert_eq!(policy.query_policy().sensitivity_for("visible_query"), None,);
    assert_eq!(policy.body_policy().sensitivity_for("visible_body"), None,);
    assert_eq!(
        policy
            .header_policy()
            .sensitivity_for("tenant_visible_header"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        policy
            .query_policy()
            .sensitivity_for("tenant_visible_query"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        policy.body_policy().sensitivity_for("tenant_visible_body"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        policy
            .header_policy()
            .sensitivity_for("tenant_public_header"),
        None,
    );
    assert_eq!(
        policy.query_policy().sensitivity_for("tenant_public_query"),
        None,
    );
    assert_eq!(
        policy.body_policy().sensitivity_for("tenant_public_body"),
        None,
    );
}

/// Verifies invalid context rules remain fallible until the HTTP snapshot is
/// built.
#[test]
fn test_http_redaction_policy_builder_reports_invalid_context_rule() {
    assert_eq!(
        HttpRedactionPolicy::builder()
            .raise_header("---", Sensitivity::High)
            .build(),
        Err(PolicyError::EmptyFieldName),
    );
}

/// Verifies the new status vocabulary and result type are publicly usable.
#[test]
fn test_body_redaction_public_types_are_available() {
    let statuses = [
        BodyRedactionStatus::Empty,
        BodyRedactionStatus::Structured,
        BodyRedactionStatus::PassedThrough,
        BodyRedactionStatus::Redacted(BodyRedactionReason::OpaqueText),
        BodyRedactionStatus::Binary,
    ];
    let _: Option<BodyRedaction> = None;
    let _: for<'a> fn(&'a BodyRedaction) -> &'a LogSafeText<'static> =
        BodyRedaction::log_safe_text;
    let _: fn(BodyRedaction) -> LogSafeText<'static> =
        BodyRedaction::into_log_safe_text;
    let _: fn(&BodyRedaction) -> BodyRedactionStatus = BodyRedaction::status;
    let _: fn(&BodyRedaction) -> usize = BodyRedaction::captured_len;
    let _: fn(&BodyRedaction) -> Option<usize> = BodyRedaction::source_len;
    let _: fn(&BodyRedaction) -> Option<usize> = BodyRedaction::omitted_len;
    let _: fn(&BodyRedaction) -> bool = BodyRedaction::is_truncated;

    assert_display::<BodyRedaction>();

    assert_eq!(statuses.len(), 5);
}
