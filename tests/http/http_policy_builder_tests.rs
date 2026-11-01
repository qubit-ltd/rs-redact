// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for HTTP policy builder behavior.

use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::formats::http::TextBodyPolicy;
use qubit_redact::formats::http::UrlPathPolicy;
/// Verifies the HTTP builder updates its independently configured choices.
#[test]
fn test_http_policy_builder_updates_behavior_choices() {
    let builder = RedactionPolicy::default()
        .to_builder()
        .http(|http| {
            http.url_path(UrlPathPolicy::Redact);
            http.text_body(TextBodyPolicy::PassThrough);
        })
        .expect("the HTTP policy configuration must be valid");
    let policy = builder.build().expect("the configured policy must be valid");

    assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Redact);
    assert_eq!(policy.http().text_body_policy(), TextBodyPolicy::PassThrough,);
}

/// Verifies that an ignored context-rule error aborts the complete HTTP draft.
#[test]
fn test_http_policy_builder_rejects_an_ignored_context_error() {
    let result = RedactionPolicy::default().to_builder().http(|http| {
        let _ = http.header().raise("x-valid", Sensitivity::Secret);
        let _ = http.header().raise("", Sensitivity::Secret);
    });

    assert!(result.is_err(), "an invalid HTTP draft must not be committed");
}

#[test]
fn test_context_floor_replaces_previous_custom_rules() {
    let first = RedactionFloor::builder()
        .raise("x-alpha", Sensitivity::Secret)
        .expect("valid first rule")
        .build()
        .expect("valid first floor");
    let second = RedactionFloor::builder()
        .raise("x-beta", Sensitivity::High)
        .expect("valid second rule")
        .build()
        .expect("valid second floor");
    let policy = RedactionPolicy::standard()
        .to_builder()
        .http(|http| {
            http.header().floor(first).floor(second);
        })
        .expect("valid HTTP draft")
        .build()
        .expect("valid policy");
    assert_eq!(policy.http().header_rules().sensitivity_for("x-alpha"), None);
    assert_eq!(
        policy.http().header_rules().sensitivity_for("x-beta"),
        Some(Sensitivity::High)
    );
    assert_eq!(policy.sensitivity_for("password"), Some(Sensitivity::Secret));
}
