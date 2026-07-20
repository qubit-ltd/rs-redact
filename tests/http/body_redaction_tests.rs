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
    let policy = HttpRedactionPolicyBuilder::default().build();

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

    let policy = HttpRedactionPolicy::builder(base)
        .header_policy(header.clone())
        .query_policy(query.clone())
        .body_policy(body.clone())
        .body_budget(budget)
        .build();

    assert_eq!(policy.header_policy(), &header);
    assert_eq!(policy.query_policy(), &query);
    assert_eq!(policy.body_policy(), &body);
    assert_eq!(policy.body_budget(), budget);
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
