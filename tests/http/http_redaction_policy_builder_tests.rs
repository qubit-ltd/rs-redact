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
