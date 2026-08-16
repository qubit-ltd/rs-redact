// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the unified base, HTTP, URI, and limit policy views.

#![cfg(all(feature = "http", feature = "uri"))]

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::http::HttpRedactor;
use qubit_redact::http::UrlPathPolicy;
use qubit_redact::uri::UriFragmentPolicy;
use qubit_redact::uri::UriPathPolicy;
use qubit_redact::uri::UriRedactor;
/// Verifies that context views share one policy and cannot lower base safety.
#[test]
fn test_unified_policy_views_share_configuration_and_protection() {
    let diagnostic_limit = InputOutputLimit::builder()
        .max_input_bytes(128)
        .max_output_bytes(256)
        .build()
        .expect("the diagnostic limit should be valid");
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .raise("access_token", Sensitivity::Secret)
        .expect("the base field should be valid");
    builder
        .http()
        .query()
        .raise("access_token", Sensitivity::Low)
        .expect("the query field should be valid");
    builder.http().url_path(UrlPathPolicy::Redact);
    builder.uri().path(UriPathPolicy::Redact);
    builder.uri().fragment(UriFragmentPolicy::Preserve);
    builder.limits().diagnostic_event(diagnostic_limit);
    let policy = builder.build().expect("the unified policy should be valid");

    assert_eq!(policy.limits().diagnostic_event(), diagnostic_limit);
    assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Redact);
    assert_eq!(policy.uri().path_policy(), UriPathPolicy::Redact);
    assert_eq!(policy.uri().fragment_policy(), UriFragmentPolicy::Preserve,);

    let http = HttpRedactor::new(policy.clone());
    assert!(
        !http
            .redact_form("access_token=raw-token")
            .to_string()
            .contains("raw-token",)
    );
    assert!(
        !http
            .redact_url_str("https://example.test/tenant/raw-token")
            .to_string()
            .contains("raw-token")
    );

    let uri = UriRedactor::new(policy);
    assert!(
        !uri.redact_uri_str("s3://bucket/tenant/raw-token#visible")
            .to_string()
            .contains("raw-token")
    );
}
