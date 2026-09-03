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

/// Exercises malformed escapes before and after an established HTTP prefix.
#[test]
fn test_nested_url_malformed_escape_variants_fail_closed() {
    let redactor = Redactor::standard();
    for nested in [
        "http://inner.test/%ZZ?token=raw-secret",
        "http%ZZ://inner.test/?token=raw-secret",
        "http%3A%2F%2Finner.test%2F%3Ftoken%3Draw-secret%",
        "http%3A%2F%2Finner.test%2F%3Ftoken%3Draw-secret%G0",
        "http%3A%2F%2Finner.test%2F%3Ftoken%3Draw-secret%FF",
    ] {
        let rendered = redact_url(&redactor, &format!("https://outer.test/?next={nested}"));
        assert!(!rendered.contains("raw-secret"), "malformed candidate leaked: {nested}");
    }
}

/// Non-HTTP schemes and malformed non-URL values remain ordinary query data.
#[test]
fn test_nested_url_detector_ignores_non_http_values() {
    let redactor = Redactor::standard();
    let non_http = redact_url(&redactor, "https://outer.test/?next=ftp://inner.test/public");
    let malformed_text = redact_url(&redactor, "https://outer.test/?next=note%25FFpublic");

    assert!(non_http.contains("ftp"));
    assert!(malformed_text.contains("note"));
}
