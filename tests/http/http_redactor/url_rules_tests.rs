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
