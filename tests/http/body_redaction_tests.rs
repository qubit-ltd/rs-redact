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
        HttpFieldContext,
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
    let policy = RedactionPolicy::default();

    assert_eq!(policy.http().header_rules().floor(), None);
    assert_eq!(policy.http().query_rules().floor(), None);
    assert_eq!(policy.http().body_rules().floor(), None);
    assert_eq!(policy.body_budget().max_input_bytes(), 16 * 1024);
    assert_eq!(policy.body_budget().max_output_bytes(), 64 * 1024);
}

/// Verifies the HTTP builder has no field rules.
#[test]
fn test_http_redaction_policy_builder_has_no_field_rules() {
    let policy = RedactionPolicy::builder()
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
        .expect("the test builder input should be valid")
        .build()
        .expect("header policy should be valid");
    let query = RedactionPolicy::builder()
        .raise("query_secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("query policy should be valid");
    let body = RedactionPolicy::builder()
        .raise("body_secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("body policy should be valid");
    let budget = BodyBudget::new(32, 48).expect("budget should be valid");

    let policy = RedactionPolicy::builder_from(&base)
        .http_disable_all_floors()
        .http_rules(HttpFieldContext::Header, header.rules().clone())
        .http_rules(HttpFieldContext::Query, query.rules().clone())
        .http_rules(HttpFieldContext::Body, body.rules().clone())
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

    let policy = RedactionPolicy::builder_from(&base)
        .http_disable_all_floors()
        .http_raise(
            HttpFieldContext::Header,
            "header_secret",
            Sensitivity::High,
        )
        .expect("the test builder input should be valid")
        .http_override_level(
            HttpFieldContext::Header,
            "header_secret",
            Sensitivity::Low,
        )
        .expect("the test builder input should be valid")
        .http_raise(
            HttpFieldContext::Header,
            "visible_header",
            Sensitivity::Secret,
        )
        .expect("the test builder input should be valid")
        .http_allow_exact(HttpFieldContext::Header, "visible_header")
        .expect("the test builder input should be valid")
        .http_raise(
            HttpFieldContext::Header,
            "public_header",
            Sensitivity::Secret,
        )
        .expect("the test builder input should be valid")
        .http_allow_suffix(HttpFieldContext::Header, "public_header")
        .expect("the test builder input should be valid")
        .http_raise(
            HttpFieldContext::Query,
            "query_secret",
            Sensitivity::Secret,
        )
        .expect("the test builder input should be valid")
        .http_override_level(
            HttpFieldContext::Query,
            "query_secret",
            Sensitivity::Medium,
        )
        .expect("the test builder input should be valid")
        .http_raise(
            HttpFieldContext::Query,
            "visible_query",
            Sensitivity::Secret,
        )
        .expect("the test builder input should be valid")
        .http_allow_exact(HttpFieldContext::Query, "visible_query")
        .expect("the test builder input should be valid")
        .http_raise(
            HttpFieldContext::Query,
            "public_query",
            Sensitivity::Secret,
        )
        .expect("the test builder input should be valid")
        .http_allow_suffix(HttpFieldContext::Query, "public_query")
        .expect("the test builder input should be valid")
        .http_raise(HttpFieldContext::Body, "body_secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .http_override_level(
            HttpFieldContext::Body,
            "body_secret",
            Sensitivity::High,
        )
        .expect("the test builder input should be valid")
        .http_raise(HttpFieldContext::Body, "visible_body", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .http_allow_exact(HttpFieldContext::Body, "visible_body")
        .expect("the test builder input should be valid")
        .http_raise(HttpFieldContext::Body, "public_body", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .http_allow_suffix(HttpFieldContext::Body, "public_body")
        .expect("the test builder input should be valid")
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

/// Verifies invalid context rules fail at the setter that receives them.
#[test]
fn test_http_redaction_policy_builder_rejects_invalid_context_rule_immediately()
{
    assert_eq!(
        RedactionPolicy::builder()
            .http_raise(HttpFieldContext::Header, "---", Sensitivity::High)
            .expect_err("an empty header field name must fail immediately"),
        PolicyError::EmptyFieldName {
            location: PolicyLocation::HttpHeader,
        },
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
