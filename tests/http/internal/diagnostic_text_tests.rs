// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for safe diagnostic body text.

use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::http::BodyCapture;
use qubit_redact::http::HttpRedactor;
use qubit_redact::http::InputOutputLimit;
use qubit_redact::http::TextBodyPolicy;
/// Verifies diagnostic text escapes line controls before display.
#[test]
fn test_diagnostic_text_escapes_newline() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("the HTTP policy should be valid");
    let rendered = HttpRedactor::new(policy)
        .redact_body(
            BodyCapture::complete(b"first\nsecond"),
            Some(&HeaderValue::from_static("text/plain")),
        )
        .to_string();

    assert_eq!(rendered, r"first\nsecond");
}

/// Verifies diagnostic text discovers and redacts embedded HTTP URLs.
#[test]
fn test_diagnostic_text_redacts_embedded_url() {
    let budget = InputOutputLimit::new(128, 128)
        .expect("the diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the HTTP policy should be valid");
    let rendered = HttpRedactor::new(policy)
        .redact_urls_in_text("visit https://example.test/?password=secret now")
        .to_string();

    assert!(!rendered.contains("password=secret"));
}
