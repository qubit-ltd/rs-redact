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
use qubit_redact::http::{
    BodyCapture,
    HttpRedactor,
    TextBodyPolicy,
};

/// Verifies diagnostic text escapes line controls before display.
#[test]
fn test_diagnostic_text_escapes_newline() {
    let policy = RedactionPolicy::builder()
        .text_body_policy(TextBodyPolicy::PassThrough)
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
