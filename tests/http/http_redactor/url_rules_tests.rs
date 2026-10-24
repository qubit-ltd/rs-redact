// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for nested URL redaction limits.

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;

use crate::http::support::redaction::redact_url;

/// Input rejection must happen before URL parsing, otherwise a truncated
/// userinfo password can be reinterpreted as a port.
#[test]
fn test_url_input_limit_never_reinterprets_userinfo_password_as_port() {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .limits(|limits| {
            limits.max_input_bytes("https://alice:1234".len());
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let output = Redactor::new(policy).redact_http_url("https://alice:1234@example.test/");
    assert!(!output.text().as_str().contains("1234"));
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
}
/// Verifies excessive nested URL recursion fails closed without exposing
/// secrets.
#[test]
fn test_url_rules_limit_nested_url_recursion() {
    let mut nested = "https://deep-user:deep-secret@inner.test/private".to_owned();
    for layer in 0..10 {
        let encoded = nested
            .replace('%', "%25")
            .replace(':', "%3A")
            .replace('/', "%2F")
            .replace('@', "%40")
            .replace('?', "%3F")
            .replace('&', "%26")
            .replace('=', "%3D");
        nested = format!("https://layer-{layer}.test/?next={encoded}");
    }

    let rendered = redact_url(&Redactor::standard(), &nested);

    assert!(!rendered.contains("deep-user"));
    assert!(!rendered.contains("deep-secret"));
    assert!(
        rendered.contains("nested") && rendered.contains("limit") && rendered.contains("exceeded"),
        "unexpected redaction: {}",
        rendered,
    );
}

/// Strict HTTP redaction applies the path policy to opaque URLs as well.
#[test]
fn test_strict_url_path_policy_redacts_opaque_url_paths() {
    let redactor = Redactor::strict();

    for url in ["mailto:private@example.com", "data:text/plain,raw-secret"] {
        let output = redactor.redact_http_url(url);

        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
        assert!(!output.text().as_str().contains("private@example.com"), "{url}");
        assert!(!output.text().as_str().contains("raw-secret"), "{url}");
        assert!(
            redactor
                .inspect_http_url(url)
                .expect("valid opaque URL")
                .contains_sensitive()
        );
    }
}

/// Invalid query escapes retain their structured reason through public APIs.
#[test]
fn test_invalid_query_reason_survives_http_publication() {
    let redactor = Redactor::standard();
    for query in ["value=%ZZ", "value=%", "value=%FF"] {
        let url = format!("https://example.test/?{query}");
        let direct = redactor.redact_http_url(&url);
        assert!(direct.summary().reasons().contains(RedactionReason::InvalidUri));
        assert_eq!(direct.summary().completion(), RedactionCompletion::Complete);
        let composed = redactor
            .text_composer()
            .http(|http| {
                http.url(&url);
            })
            .finish();
        assert!(composed.summary().reasons().contains(RedactionReason::InvalidUri));
        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_http_url(&url);
        let published = batch.finish();
        assert!(published.summary().reasons().contains(RedactionReason::InvalidUri));
        assert_eq!(published.text(handle).as_str(), direct.text().as_str());
    }
}

/// Valid percent escapes do not report an invalid URI.
#[test]
fn test_valid_percent_encoded_query_has_no_invalid_uri_reason() {
    let output = Redactor::standard().redact_http_url("https://example.test/?value=%41");

    assert!(!output.summary().reasons().contains(RedactionReason::InvalidUri));
}

/// Invalid query provenance is retained when it occurs in a nested URL.
#[test]
fn test_nested_invalid_query_retains_invalid_uri_reason() {
    let nested = "https://inner.test/?value=%ZZ";
    let encoded = url::form_urlencoded::byte_serialize(nested.as_bytes()).collect::<String>();
    let output = Redactor::standard().redact_http_url(&format!("https://outer.test/?next={encoded}"));

    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
}

/// Invalid-query provenance is retained alongside output truncation.
#[test]
fn test_invalid_query_reason_survives_output_limit() {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .limits(|limits| {
            limits.max_output_bytes(32);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let output = Redactor::new(policy).redact_http_url("https://example.test/?value=abcdefghijklmnopqrstuvwxyz%ZZ");

    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(output.text().as_str().len() <= 32);
    assert!(matches!(
        output.summary().completion(),
        RedactionCompletion::Truncated | RedactionCompletion::Exhausted,
    ));
}
