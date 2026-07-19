// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internal multipart part sanitization behavior.

use http::HeaderValue;

use qubit_sanitize::{
    BodySanitizationStatus,
    HttpBodySanitizer,
    NameMatchMode,
    SensitivityLevel,
    TextBodyPolicy,
};

#[test]
fn test_http_body_sanitizer_escapes_multipart_sensitive_value_controls() {
    let mut sanitizer = HttpBodySanitizer::default();
    sanitizer
        .field_sanitizer_mut()
        .set_sensitive_field_level("session", SensitivityLevel::Medium);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let cases: [(&str, &[u8], &str); 4] = [
        (
            "line feed",
            b"--b\r\nContent-Disposition: form-data; name=\"session\"\r\n\r\nabcdef\n\r\n--b--\r\n",
            r"session=****\n",
        ),
        (
            "carriage return",
            b"--b\r\nContent-Disposition: form-data; name=\"session\"\r\n\r\nabcdef\r\r\n--b--\r\n",
            r"session=****\r",
        ),
        (
            "tab",
            b"--b\r\nContent-Disposition: form-data; name=\"session\"\r\n\r\nabcdef\t\r\n--b--\r\n",
            r"session=****\t",
        ),
        (
            "escape",
            b"--b\r\nContent-Disposition: form-data; name=\"session\"\r\n\r\nabcdef\x1b\r\n--b--\r\n",
            r"session=****\u{1b}",
        ),
    ];

    for (label, body, expected) in cases {
        let result = sanitizer.sanitize_body(
            body,
            Some(&content_type),
            NameMatchMode::ExactOrSuffix,
        );

        assert!(
            result.raw_content().contains(expected),
            "{label}: {}",
            result.raw_content(),
        );
    }
}

#[test]
fn test_http_body_sanitizer_reports_multipart_text_as_passed_through() {
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let body = b"--b\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain\r\n\r\nvisible text\r\n--b--\r\n";

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
}

#[test]
fn test_http_body_sanitizer_reports_mixed_multipart_as_passed_through() {
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");
    let body = b"--b\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain\r\n\r\nvisible text\r\n--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret value\r\n--b--\r\n";

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
    assert!(result.raw_content().contains("note=visible text"));
    assert!(result.raw_content().contains("password=<redacted>"));
    assert!(!result.raw_content().contains("secret value"));
}
