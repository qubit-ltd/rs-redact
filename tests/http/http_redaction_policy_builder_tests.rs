// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`HttpRedactionPolicyBuilder`](qubit_redact::http::HttpRedactionPolicyBuilder).

use qubit_redact::{
    RedactionPolicy,
    Sensitivity,
    http::{
        DiagnosticBudget,
        HttpRedactionPolicy,
        HttpRedactionPolicyBuilder,
        TextBodyPolicy,
        UnkeyedJsonValuePolicy,
        UrlPathPolicy,
    },
};

/// Alternate body-policy setter used as an unselected function target.
fn alternate_body_policy(
    builder: HttpRedactionPolicyBuilder,
    _policy: RedactionPolicy,
) -> HttpRedactionPolicyBuilder {
    builder
}

/// Alternate URL-path setter used as an unselected function target.
const fn alternate_url_path_policy(
    builder: HttpRedactionPolicyBuilder,
    _policy: UrlPathPolicy,
) -> HttpRedactionPolicyBuilder {
    builder
}

/// Alternate text-body setter used as an unselected function target.
const fn alternate_text_body_policy(
    builder: HttpRedactionPolicyBuilder,
    _policy: TextBodyPolicy,
) -> HttpRedactionPolicyBuilder {
    builder
}

/// Alternate unkeyed-value setter used as an unselected function target.
const fn alternate_unkeyed_json_value_policy(
    builder: HttpRedactionPolicyBuilder,
    _policy: UnkeyedJsonValuePolicy,
) -> HttpRedactionPolicyBuilder {
    builder
}

/// Builds an HTTP policy whose three contexts inherit exact and suffix allows.
fn inherited_allow_policy() -> HttpRedactionPolicy {
    let base = RedactionPolicy::empty_builder()
        .raise("access_token", Sensitivity::Secret)
        .raise("session_token", Sensitivity::High)
        .allow_exact("access_token")
        .allow_suffix("session_token")
        .build()
        .expect("the base policy should be valid");
    HttpRedactionPolicy::builder()
        .header_policy(base.clone())
        .query_policy(base.clone())
        .body_policy(base)
        .build()
        .expect("the HTTP policy should be valid")
}

/// Verifies the HTTP policy builder creates the default policy snapshot.
#[test]
fn test_http_redaction_policy_builder_builds_default_snapshot() {
    let policy = HttpRedactionPolicy::builder()
        .build()
        .expect("the default HTTP policy should be valid");

    assert_eq!(policy, HttpRedactionPolicy::default());
}

/// Verifies the remaining replacement and behavior setters reach the built
/// immutable policy.
#[test]
fn test_http_redaction_policy_builder_sets_body_and_behavior_policies() {
    let body = RedactionPolicy::empty_builder()
        .raise("body-secret", Sensitivity::High)
        .build()
        .expect("the body policy should be valid");
    let selected = usize::from(std::process::id() == 0);
    let body_policy: [fn(
        HttpRedactionPolicyBuilder,
        RedactionPolicy,
    ) -> HttpRedactionPolicyBuilder; 2] = [
        HttpRedactionPolicyBuilder::body_policy,
        alternate_body_policy,
    ];
    let url_path_policy: [fn(
        HttpRedactionPolicyBuilder,
        UrlPathPolicy,
    ) -> HttpRedactionPolicyBuilder; 2] = [
        HttpRedactionPolicyBuilder::url_path_policy,
        alternate_url_path_policy,
    ];
    let text_body_policy: [fn(
        HttpRedactionPolicyBuilder,
        TextBodyPolicy,
    ) -> HttpRedactionPolicyBuilder; 2] = [
        HttpRedactionPolicyBuilder::text_body_policy,
        alternate_text_body_policy,
    ];
    let unkeyed_json_value_policy: [fn(
        HttpRedactionPolicyBuilder,
        UnkeyedJsonValuePolicy,
    ) -> HttpRedactionPolicyBuilder; 2] = [
        HttpRedactionPolicyBuilder::unkeyed_json_value_policy,
        alternate_unkeyed_json_value_policy,
    ];
    let builder =
        body_policy[selected](HttpRedactionPolicy::builder(), body.clone());
    let builder = url_path_policy[selected](builder, UrlPathPolicy::Preserve);
    let builder =
        text_body_policy[selected](builder, TextBodyPolicy::PassThrough);
    let policy = unkeyed_json_value_policy[selected](
        builder,
        UnkeyedJsonValuePolicy::PassThrough,
    )
    .build()
    .expect("the HTTP policy should be valid");

    assert_eq!(policy.body_policy(), &body);
    assert_eq!(policy.url_path_policy(), UrlPathPolicy::Preserve);
    assert_eq!(policy.text_body_policy(), TextBodyPolicy::PassThrough);
    assert_eq!(
        policy.unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::PassThrough,
    );
}

/// Verifies custom diagnostic limits survive building and rebuilding a policy.
#[test]
fn test_http_redaction_policy_builder_preserves_diagnostic_budget() {
    let budget = DiagnosticBudget::new(128, 256)
        .expect("the custom diagnostic budget should be valid");
    let policy = HttpRedactionPolicy::builder()
        .diagnostic_budget(budget)
        .build()
        .expect("the HTTP policy should be valid");
    let rebuilt = HttpRedactionPolicyBuilder::from_policy(&policy)
        .build()
        .expect("the copied HTTP policy should be valid");

    assert_eq!(policy.diagnostic_budget(), budget);
    assert_eq!(rebuilt, policy);
}

/// Verifies diagnostic limits remain independent from component-policy setter
/// order.
#[test]
fn test_http_redaction_policy_builder_keeps_diagnostic_budget_independent() {
    let selected = DiagnosticBudget::new(128, 256)
        .expect("the selected budget should be valid");
    let replaced = DiagnosticBudget::new(512, 1024)
        .expect("the replacement budget should be valid");
    let body = RedactionPolicy::builder()
        .diagnostic_budget(replaced)
        .build()
        .expect("the body policy should be valid");

    let budget_before_body = HttpRedactionPolicy::builder()
        .diagnostic_budget(selected)
        .body_policy(body.clone())
        .build()
        .expect("the HTTP policy should be valid");
    let budget_after_body = HttpRedactionPolicy::builder()
        .body_policy(body)
        .diagnostic_budget(selected)
        .build()
        .expect("the HTTP policy should be valid");

    assert_eq!(budget_before_body.diagnostic_budget(), selected);
    assert_eq!(budget_after_body.diagnostic_budget(), selected);
}

/// Verifies validation reaches invalid query and body builders after earlier
/// contexts succeed.
#[test]
fn test_http_redaction_policy_builder_validates_each_context_in_order() {
    let invalid_query = HttpRedactionPolicy::builder()
        .raise_query("---", Sensitivity::High)
        .build();
    let invalid_body = HttpRedactionPolicy::builder()
        .raise_body("---", Sensitivity::High)
        .build();

    assert!(invalid_query.is_err());
    assert!(invalid_body.is_err());
}

/// Verifies context-specific builders can revoke inherited allow rules.
#[test]
fn test_http_redaction_policy_builder_removes_inherited_allow_rules() {
    let policy =
        HttpRedactionPolicyBuilder::from_policy(&inherited_allow_policy())
            .remove_header_allow_exact("access-token")
            .remove_query_allow_suffix("session-token")
            .clear_body_allow_rules()
            .build()
            .expect("the rebuilt HTTP policy should be valid");

    assert_eq!(
        policy.header_policy().sensitivity_for("access_token"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        policy
            .query_policy()
            .sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );
    assert_eq!(
        policy.body_policy().sensitivity_for("access_token"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        policy
            .body_policy()
            .sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );
}

/// Verifies every context-specific allow-rule revocation reaches its matching
/// field policy without changing the other allow rule.
#[test]
fn test_http_redaction_policy_builder_revokes_each_remaining_allow_rule() {
    let original = inherited_allow_policy();

    let header_suffix = HttpRedactionPolicyBuilder::from_policy(&original)
        .remove_header_allow_suffix("session-token")
        .build()
        .expect("the rebuilt header policy should be valid");
    assert_eq!(
        header_suffix
            .header_policy()
            .sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );
    assert_eq!(
        header_suffix
            .header_policy()
            .sensitivity_for("access_token"),
        None
    );

    let header_clear = HttpRedactionPolicyBuilder::from_policy(&original)
        .clear_header_allow_rules()
        .build()
        .expect("the rebuilt header policy should be valid");
    assert_eq!(
        header_clear.header_policy().sensitivity_for("access_token"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        header_clear
            .header_policy()
            .sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );

    let query_exact = HttpRedactionPolicyBuilder::from_policy(&original)
        .remove_query_allow_exact("access-token")
        .build()
        .expect("the rebuilt query policy should be valid");
    assert_eq!(
        query_exact.query_policy().sensitivity_for("access_token"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        query_exact
            .query_policy()
            .sensitivity_for("request_session_token"),
        None,
    );

    let query_clear = HttpRedactionPolicyBuilder::from_policy(&original)
        .clear_query_allow_rules()
        .build()
        .expect("the rebuilt query policy should be valid");
    assert_eq!(
        query_clear.query_policy().sensitivity_for("access_token"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        query_clear
            .query_policy()
            .sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );

    let body_exact = HttpRedactionPolicyBuilder::from_policy(&original)
        .remove_body_allow_exact("access-token")
        .build()
        .expect("the rebuilt body policy should be valid");
    assert_eq!(
        body_exact.body_policy().sensitivity_for("access_token"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        body_exact
            .body_policy()
            .sensitivity_for("request_session_token"),
        None,
    );

    let body_suffix = HttpRedactionPolicyBuilder::from_policy(&original)
        .remove_body_allow_suffix("session-token")
        .build()
        .expect("the rebuilt body policy should be valid");
    assert_eq!(
        body_suffix.body_policy().sensitivity_for("access_token"),
        None
    );
    assert_eq!(
        body_suffix
            .body_policy()
            .sensitivity_for("request_session_token"),
        Some(Sensitivity::High),
    );
}
