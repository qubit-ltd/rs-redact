// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Coverage for grouped policy-builder views and their snapshot accessors.

#![cfg(all(feature = "http", feature = "uri", feature = "json"))]

use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::UnkeyedJsonValuePolicy;
use qubit_redact::formats::http::TextBodyPolicy;
use qubit_redact::formats::http::UrlPathPolicy;
use qubit_redact::formats::uri::UriFragmentPolicy;
use qubit_redact::formats::uri::UriPathPolicy;

/// Exercises the grouped HTTP and URI views through a committed policy
/// snapshot.
#[test]
fn test_grouped_policy_views_cover_configurable_settings() {
    let floor = RedactionFloor::builder()
        .raise("credential", Sensitivity::High)
        .expect("floor field name should be valid")
        .build()
        .expect("floor should be valid");

    let policy = RedactionPolicy::builder()
        .http(|http| {
            http.header()
                .raise("x-api-key", Sensitivity::Secret)
                .expect("header field name should be valid");
            http.query()
                .raise("access_token", Sensitivity::High)
                .expect("query field name should be valid");
            http.body()
                .raise("session", Sensitivity::Medium)
                .expect("body field name should be valid");
            http.url_path(UrlPathPolicy::Redact)
                .text_body(TextBodyPolicy::PassThrough)
                .floor_all(floor.clone())
                .disable_all_floors()
                .unkeyed_json(UnkeyedJsonValuePolicy::Redact);
        })
        .expect("HTTP settings should be valid")
        .uri(|uri| {
            uri.path(UriPathPolicy::Redact).fragment(UriFragmentPolicy::Preserve);
        })
        .expect("URI settings should be valid")
        .build()
        .expect("policy should be valid");

    assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Redact);
    assert_eq!(policy.http().text_body_policy(), TextBodyPolicy::PassThrough);
    assert_eq!(
        policy.http().header_rules().sensitivity_for("x-api-key"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        policy.http().query_rules().sensitivity_for("access_token"),
        Some(Sensitivity::High)
    );
    assert_eq!(
        policy.http().body_rules().sensitivity_for("session"),
        Some(Sensitivity::Medium)
    );
    assert!(policy.http().header_rules().floor().is_none());
    assert!(policy.http().query_rules().floor().is_none());
    assert!(policy.http().body_rules().floor().is_none());
    assert_eq!(policy.unkeyed_json_value_policy(), UnkeyedJsonValuePolicy::Redact);
    assert_eq!(policy.uri().path_policy(), UriPathPolicy::Redact);
    assert_eq!(policy.uri().fragment_policy(), UriFragmentPolicy::Preserve);
}
