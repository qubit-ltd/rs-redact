// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for borrowed HTTP field-rule execution.

use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::http::HttpRedactor;
/// Verifies header field execution uses the shared mask table atomically.
#[test]
fn test_field_redactor_uses_application_mask_for_header_rule() {
    let floor = RedactionFloor::builder()
        .raise("tenant_token", Sensitivity::Low)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should be valid");
    let application = RedactionPolicy::builder()
        .disable_floor()
        .raise("tenant_token", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .mask(
            Sensitivity::Secret,
            MaskPolicy::fixed("[application-secret]"),
        )
        .expect("the test mask policy should be valid")
        .build()
        .expect("the application policy should be valid");
    let mut builder = RedactionPolicy::builder();
    builder
        .http()
        .header()
        .replace_rules(application.rules().clone().with_floor(floor));
    let policy = builder
        .mask(
            Sensitivity::Secret,
            MaskPolicy::fixed("[application-secret]"),
        )
        .expect("the test mask policy should be valid")
        .build()
        .expect("the HTTP policy should be valid");
    let mut headers = HeaderMap::new();
    headers.insert("tenant-token", HeaderValue::from_static("source-secret"));

    let rendered = HttpRedactor::new(policy)
        .redact_headers(&headers)
        .to_string();

    assert!(rendered.contains("[application-secret]"));
    assert!(!rendered.contains("source-secret"));
}
