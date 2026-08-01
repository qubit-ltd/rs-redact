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
    PolicyLocation,
    RedactionPolicy,
    Sensitivity,
    http::{
        BodyBudget,
        BodyCapture,
        BodyRedaction,
        BodyRedactionReason,
        BodyRedactionStatus,
        HttpRedactionPolicy,
        HttpRedactor,
    },
};

/// Asserts at compile time that a public result implements [`Display`].
fn assert_display<T: Display>() {}

/// Alternate text query used as the unselected function-pointer target.
fn alternate_log_safe_text(body: &BodyRedaction) -> &LogSafeText<'static> {
    body.log_safe_text()
}

/// Alternate captured-length query used as an unselected target.
const fn alternate_captured_len(_body: &BodyRedaction) -> usize {
    usize::MAX
}

/// Alternate omitted-length query used as an unselected target.
const fn alternate_omitted_len(_body: &BodyRedaction) -> Option<usize> {
    None
}

/// Alternate truncation query used as an unselected target.
const fn alternate_is_truncated(_body: &BodyRedaction) -> bool {
    false
}

/// Verifies HTTP defaults use independent policy snapshots and hard budgets.
#[test]
fn test_http_redaction_policy_default_uses_safe_values() {
    let policy = HttpRedactionPolicy::default();

    assert_eq!(policy.header_rules(), RedactionPolicy::default().rules(),);
    assert_eq!(policy.query_rules(), RedactionPolicy::default().rules());
    assert_eq!(policy.body_rules(), RedactionPolicy::default().rules());
    assert_eq!(policy.body_budget().max_input_bytes(), 16 * 1024);
    assert_eq!(policy.body_budget().max_output_bytes(), 64 * 1024);
}

/// Verifies the HTTP builder has no field rules.
#[test]
fn test_http_redaction_policy_builder_has_no_field_rules() {
    let policy = HttpRedactionPolicy::builder()
        .disable_floor()
        .build()
        .expect("HTTP redaction policy should be valid");

    assert_eq!(policy.header_rules().sensitivity_for("authorization"), None);
    assert_eq!(policy.query_rules().sensitivity_for("password"), None);
    assert_eq!(policy.body_rules().sensitivity_for("password"), None);
}

/// Verifies each HTTP context can receive an independent immutable snapshot.
#[test]
fn test_http_redaction_policy_builder_overrides_each_context() {
    let base = RedactionPolicy::default();
    let header = RedactionPolicy::builder()
        .raise("header_secret", Sensitivity::Secret)
        .build()
        .expect("header policy should be valid");
    let query = RedactionPolicy::builder()
        .raise("query_secret", Sensitivity::Secret)
        .build()
        .expect("query policy should be valid");
    let body = RedactionPolicy::builder()
        .raise("body_secret", Sensitivity::Secret)
        .build()
        .expect("body policy should be valid");
    let budget = BodyBudget::new(32, 48).expect("budget should be valid");

    let policy = HttpRedactionPolicy::builder_from(&base)
        .disable_floor()
        .header_rules(header.rules().clone())
        .query_rules(query.rules().clone())
        .body_rules(body.rules().clone())
        .body_budget(budget)
        .build()
        .expect("HTTP redaction policy should be valid");

    assert_eq!(policy.header_rules(), header.rules());
    assert_eq!(policy.query_rules(), query.rules());
    assert_eq!(policy.body_rules(), body.rules());
    assert_eq!(policy.body_budget(), budget);
}

/// Verifies one upstream builder owns independent mutable rules for every
/// HTTP field context.
#[test]
fn test_http_redaction_policy_builder_configures_context_rules() {
    let base = RedactionPolicy::builder()
        .build()
        .expect("empty base policy should be valid");

    let policy = HttpRedactionPolicy::builder_from(&base)
        .disable_floor()
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
        policy.header_rules().sensitivity_for("header_secret"),
        Some(Sensitivity::Low),
    );
    assert_eq!(
        policy.query_rules().sensitivity_for("query_secret"),
        Some(Sensitivity::Medium),
    );
    assert_eq!(
        policy.body_rules().sensitivity_for("body_secret"),
        Some(Sensitivity::High),
    );
    assert_eq!(
        policy.header_rules().sensitivity_for("visible_header"),
        None,
    );
    assert_eq!(policy.query_rules().sensitivity_for("visible_query"), None,);
    assert_eq!(policy.body_rules().sensitivity_for("visible_body"), None,);
    assert_eq!(
        policy
            .header_rules()
            .sensitivity_for("tenant_visible_header"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        policy.query_rules().sensitivity_for("tenant_visible_query"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        policy.body_rules().sensitivity_for("tenant_visible_body"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        policy
            .header_rules()
            .sensitivity_for("tenant_public_header"),
        None,
    );
    assert_eq!(
        policy.query_rules().sensitivity_for("tenant_public_query"),
        None,
    );
    assert_eq!(
        policy.body_rules().sensitivity_for("tenant_public_body"),
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
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::HttpHeader,
        }),
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

/// Verifies body-result queries expose the captured source metadata.
#[test]
fn test_body_redaction_queries_expose_captured_metadata() {
    let body = HttpRedactor::default().redact_body(
        BodyCapture::truncated(b"visible", Some(10))
            .expect("the capture metadata should be valid"),
        None,
    );
    let selected = usize::from(std::process::id() == 0);
    let log_safe_text: [for<'a> fn(
        &'a BodyRedaction,
    ) -> &'a LogSafeText<'static>; 2] =
        [BodyRedaction::log_safe_text, alternate_log_safe_text];
    let captured_len: [fn(&BodyRedaction) -> usize; 2] =
        [BodyRedaction::captured_len, alternate_captured_len];
    let omitted_len: [fn(&BodyRedaction) -> Option<usize>; 2] =
        [BodyRedaction::omitted_len, alternate_omitted_len];
    let is_truncated: [fn(&BodyRedaction) -> bool; 2] =
        [BodyRedaction::is_truncated, alternate_is_truncated];

    assert!(!log_safe_text[selected](&body).as_ref().is_empty());
    assert_eq!(captured_len[selected](&body), 7);
    assert_eq!(omitted_len[selected](&body), Some(3));
    assert!(is_truncated[selected](&body));
}
