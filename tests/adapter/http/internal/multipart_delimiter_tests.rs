// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internal multipart delimiter handling behavior.

use http::HeaderValue;

use qubit_redact::{
    HttpBodySanitizer,
    NameMatchMode,
};

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_multipart_mixed_without_boundary()
 {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("multipart/mixed");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"password\"\r\n\
\r\n\
secret-password\r\n\
--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: multipart body>");
    assert!(!sanitized.contains("secret-password"));
    assert!(!sanitized.contains("boundary"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_multipart_text_containing_boundary_text()
 {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"description\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
plain text mentions --boundary inside the value\r\n\
--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.contains("description=<redacted: multipart text part>"));
    assert!(
        !sanitized.contains("plain text mentions --boundary inside the value")
    );
    assert!(!sanitized.contains("<redacted: multipart body>"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_malformed_multipart() {
    let sanitizer = HttpBodySanitizer::default();
    let cases: [(&str, &'static [u8], &str); 6] = [
        (
            "missing closing delimiter",
            b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret",
            "multipart/form-data; boundary=boundary",
        ),
        (
            "malformed closing delimiter",
            b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret\r\n--boundary--extra",
            "multipart/form-data; boundary=boundary",
        ),
        (
            "malformed part header",
            b"--boundary\r\nContent-Disposition form-data; name=\"password\"\r\n\r\nsecret\r\n--boundary--",
            "multipart/form-data; boundary=boundary",
        ),
        (
            "empty boundary",
            b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret\r\n--boundary--",
            "multipart/form-data; boundary=\"\"",
        ),
        (
            "unclosed boundary quote",
            b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret\r\n--boundary--",
            "multipart/form-data; boundary=\"boundary",
        ),
        (
            "trailing text after quoted boundary",
            b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret\r\n--boundary--",
            "multipart/form-data; boundary=\"boundary\"x",
        ),
    ];

    for (label, body, content_type) in cases {
        let content_type = HeaderValue::from_bytes(content_type.as_bytes())
            .expect("content type should parse");

        let sanitized = sanitizer.sanitize_body(
            body,
            Some(&content_type),
            NameMatchMode::ExactOrSuffix,
        );
        let sanitized = sanitized.into_rendered();

        assert_eq!(sanitized, "<redacted: multipart body>", "{label}");
        assert!(!sanitized.contains("secret"), "{label}");
    }
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_multipart_without_boundary() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("multipart/form-data");
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret\r\n--boundary--";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: multipart body>");
    assert!(!sanitized.contains("secret"));
    assert!(!sanitized.contains("boundary"));
}
