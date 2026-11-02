// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for deterministic header grouping.

use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

use crate::http::support::redaction::redact_headers;
/// Verifies repeated values remain grouped beneath their sorted header name.
#[test]
fn test_headers_group_repeated_values_in_insertion_order() {
    let mut headers = HeaderMap::new();
    headers.insert("z-last", HeaderValue::from_static("z"));
    headers.append("x-visible", HeaderValue::from_static("first"));
    headers.append("x-visible", HeaderValue::from_static("second"));

    let rendered = redact_headers(RedactionPolicy::standard(), &headers);

    assert_eq!(rendered, "x-visible: [first, second]\\nz-last: [z]");
}

/// Verifies direct, composed, and batch rendering preserve native sensitivity
/// and accounting.
#[test]
fn test_headers_native_sensitive_flag_survives_all_rendering_entries() {
    let mut headers = HeaderMap::new();
    let mut private = HeaderValue::from_static("header-secret-427");
    private.set_sensitive(true);
    headers.append("x-visible", HeaderValue::from_static("first"));
    headers.append("x-visible", HeaderValue::from_static("second"));
    headers.insert("x-private", private);
    let original = headers.clone();
    let redactor = Redactor::standard();

    let direct = redactor.redact_http_headers(&headers);
    let composed = redactor
        .text_composer()
        .http(|http| {
            http.headers(&headers);
        })
        .finish();
    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_headers(&headers);
    let published = batch.finish();

    assert_eq!(
        direct.text().as_str(),
        "x-private: [<redacted>]\\nx-visible: [first, second]"
    );
    assert_eq!(composed.text(), direct.text());
    assert_eq!(published.text(handle), direct.text());
    assert_eq!(composed.summary(), direct.summary());
    assert_eq!(published.summary(), direct.summary());
    assert_eq!(headers, original);
    assert!(headers.get("x-private").unwrap().is_sensitive());
}
