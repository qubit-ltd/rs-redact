// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for HTTP body content-type selection.

use http::HeaderValue;

use qubit_sanitize::{
    HttpBodySanitizer,
    NameMatchMode,
};

#[test]
fn test_http_body_sanitizer_sanitize_body_respects_explicit_text_content_type()
{
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("text/plain");

    assert_eq!(
        sanitizer
            .sanitize_body(
                b"{not json}",
                Some(&content_type),
                NameMatchMode::Exact,
            )
            .into_rendered(),
        "<redacted: text body>",
    );
}

#[test]
fn test_http_body_sanitizer_sanitize_body_respects_explicit_form_content_type()
{
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("application/x-www-form-urlencoded");

    assert_eq!(
        sanitizer
            .sanitize_body(
                b"{=prefix&password=secret",
                Some(&content_type),
                NameMatchMode::Exact,
            )
            .into_rendered(),
        "%7B=prefix&password=%3Credacted%3E",
    );
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_invalid_content_type_header()
{
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_bytes(b"multipart/form-data; boundary=boundary\xff")
            .expect("header value with obs-text should be accepted");
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret\r\n--boundary--";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: invalid content type body>");
    assert!(!sanitized.contains("secret"));
    assert!(!sanitized.contains("boundary"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_prefers_multipart_over_json_sniffing()
{
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("multipart/mixed");

    let sanitized = sanitizer.sanitize_body(
        br#"{"password":"secret"}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: multipart body>");
    assert!(!sanitized.contains("secret"));
}
