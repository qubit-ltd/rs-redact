// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`TextBodyPolicy`](qubit_sanitize::TextBodyPolicy).

use http::HeaderValue;

use qubit_sanitize::{
    HttpBodySanitizer,
    NameMatchMode,
    TextBodyPolicy,
};

#[test]
fn test_text_body_policy_default_is_redact() {
    assert_eq!(TextBodyPolicy::default(), TextBodyPolicy::Redact);
}

#[test]
fn test_http_body_sanitizer_text_body_policy_accessors() {
    let mut sanitizer = HttpBodySanitizer::default();

    assert_eq!(sanitizer.text_body_policy(), TextBodyPolicy::Redact);
    sanitizer.set_text_body_policy(TextBodyPolicy::PassThrough);
    assert_eq!(sanitizer.text_body_policy(), TextBodyPolicy::PassThrough);

    let sanitizer = sanitizer.with_text_body_policy(TextBodyPolicy::Redact);
    assert_eq!(sanitizer.text_body_policy(), TextBodyPolicy::Redact);
}

#[test]
fn test_http_body_sanitizer_redacts_declared_text_body_by_default() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("text/plain");

    assert_eq!(
        sanitizer.sanitize_body(
            b"plain text secret",
            Some(&content_type),
            NameMatchMode::Exact,
        ),
        "<redacted: text body>",
    );
}

#[test]
fn test_http_body_sanitizer_passes_through_declared_text_body_when_enabled() {
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type = HeaderValue::from_static("text/plain");

    assert_eq!(
        sanitizer.sanitize_body(
            b"plain text secret",
            Some(&content_type),
            NameMatchMode::Exact,
        ),
        "plain text secret",
    );
}

#[test]
fn test_http_body_sanitizer_passes_through_multipart_text_part_when_enabled() {
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"description\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
plain text value\r\n\
--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert!(sanitized.contains("description=plain text value"));
}
