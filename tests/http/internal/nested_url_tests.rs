// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for nested URL redaction in structured bodies.

use qubit_redact::Redactor;

use crate::http::support::redaction::redact_url;
/// Verifies a nested URL does not expose query secrets.
#[test]
fn test_nested_url_masks_query_secret() {
    let rendered = redact_url(
        &Redactor::standard(),
        "https://outer.test/?next=https%3A%2F%2Fexample.test%2Fpath%3Fapi_key%3Draw",
    );

    assert!(!rendered.contains("raw"));
}

/// Verifies malformed percent-encoded nested URL candidates fail closed.
#[test]
fn test_malformed_nested_url_does_not_expose_query_secret() {
    let rendered = redact_url(
        &Redactor::standard(),
        "https://outer.test/?next=http%3A%2F%2Finner.test%2F%3Ftoken%3Draw-secret%ZZ",
    );

    assert!(!rendered.contains("raw-secret"));
}

/// Verifies a candidate exceeding the bounded decoding depth is not rendered
/// as an unredacted nested URL.
#[test]
fn test_deeply_encoded_nested_url_does_not_expose_query_secret() {
    let mut nested = "https://inner.test/?token=raw-secret".to_owned();
    for _ in 0..9 {
        nested = url::form_urlencoded::byte_serialize(nested.as_bytes()).collect();
    }
    let rendered = redact_url(&Redactor::standard(), &format!("https://outer.test/?next={nested}"));

    assert!(!rendered.contains("raw-secret"));
}
