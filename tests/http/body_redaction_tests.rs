// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable HTTP policy and body-result public contracts.

use std::fmt::Display;

use qubit_redact::LogSafeText;
use qubit_redact::PolicyError;
use qubit_redact::PolicyLocation;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::http::BodyBudget;
use qubit_redact::http::BodyCapture;
use qubit_redact::http::BodyRedaction;
use qubit_redact::http::BodyRedactionReason;
use qubit_redact::http::BodyRedactionStatus;
use qubit_redact::http::HttpRedactor;
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

/// Alternate completion query used as an unselected target.
const fn alternate_completion(_body: &BodyRedaction) -> RedactionCompletion {
    RedactionCompletion::Complete
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().disable_floor();
        builder
    })
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
    let header = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("header_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("header policy should be valid");
    let query = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("query_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("query policy should be valid");
    let body = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("body_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("body policy should be valid");
    let budget = BodyBudget::builder()
        .max_input_bytes(32)
        .max_output_bytes(48)
        .build()
        .expect("budget should be valid");

    let mut builder = RedactionPolicy::builder_from(&base);
    builder.http().disable_all_floors();
    builder
        .http()
        .header()
        .replace_rules(header.rules().clone());
    builder.http().query().replace_rules(query.rules().clone());
    builder.http().body().replace_rules(body.rules().clone());
    builder.limits().http_body(budget);
    let policy = builder
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

    let mut builder = RedactionPolicy::builder_from(&base);
    builder.http().disable_all_floors();
    builder
        .http()
        .header()
        .raise("header_secret", Sensitivity::High)
        .expect("the test builder input should be valid")
        .override_level("header_secret", Sensitivity::Low)
        .expect("the test builder input should be valid")
        .raise("visible_header", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .allow_exact("visible_header")
        .expect("the test builder input should be valid")
        .raise("public_header", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .allow_suffix("public_header")
        .expect("the test builder input should be valid");
    builder
        .http()
        .query()
        .raise("query_secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .override_level("query_secret", Sensitivity::Medium)
        .expect("the test builder input should be valid")
        .raise("visible_query", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .allow_exact("visible_query")
        .expect("the test builder input should be valid")
        .raise("public_query", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .allow_suffix("public_query")
        .expect("the test builder input should be valid");
    builder
        .http()
        .body()
        .raise("body_secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .override_level("body_secret", Sensitivity::High)
        .expect("the test builder input should be valid")
        .raise("visible_body", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .allow_exact("visible_body")
        .expect("the test builder input should be valid")
        .raise("public_body", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .allow_suffix("public_body")
        .expect("the test builder input should be valid");
    let policy = builder
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
    let mut builder = RedactionPolicy::builder();
    assert_eq!(
        builder
            .http()
            .header()
            .raise("---", Sensitivity::High)
            .err()
            .expect("an empty header field name must fail immediately"),
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
    let _: fn(&BodyRedaction) -> RedactionCompletion =
        BodyRedaction::completion;

    assert_display::<BodyRedaction>();

    assert_eq!(statuses.len(), 5);
}

/// Verifies body-result queries expose the captured source metadata.
#[test]
fn test_body_redaction_queries_expose_captured_metadata() {
    let body = HttpRedactor::default().redact_body(
        BodyCapture::truncated(b"visible", 10)
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
    let completion: [fn(&BodyRedaction) -> RedactionCompletion; 2] =
        [BodyRedaction::completion, alternate_completion];

    assert!(!log_safe_text[selected](&body).as_ref().is_empty());
    assert_eq!(captured_len[selected](&body), 7);
    assert_eq!(omitted_len[selected](&body), Some(3));
    assert_eq!(completion[selected](&body), RedactionCompletion::Truncated,);
}
