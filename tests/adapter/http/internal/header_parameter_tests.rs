// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internal multipart header-parameter parsing behavior.

use http::HeaderValue;

use qubit_sanitize::{
    BodyRedactionReason,
    BodySanitizationStatus,
    HttpBodySanitizer,
    NameMatchMode,
    TextBodyPolicy,
};

#[test]
fn test_http_body_sanitizer_redacts_duplicate_multipart_parameters() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let bodies = [
        "--boundary\r\nContent-Disposition: form-data; name=note; name=password\r\n\r\nsecret\r\n--boundary--\r\n",
        "--boundary\r\nContent-Disposition: form-data; name=upload; filename=public.txt; filename=secret.txt\r\n\r\nsecret\r\n--boundary--\r\n",
        "--boundary\r\nContent-Disposition: form-data; name=upload; filename*=public.txt; filename*=secret.txt\r\n\r\nsecret\r\n--boundary--\r\n",
    ];

    for body in bodies {
        let result = sanitizer.sanitize_body(
            body.as_bytes(),
            Some(&content_type),
            NameMatchMode::ExactOrSuffix,
        );

        assert_eq!(result.to_string(), "<redacted: multipart body>");
    }
}

#[test]
fn test_http_body_sanitizer_redacts_duplicate_multipart_boundaries() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static(
        "multipart/form-data; boundary=boundary; boundary=other",
    );
    let body = b"--boundary\r\n\r\n\r\n--boundary--\r\n";

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(result.to_string(), "<redacted: multipart body>");
}

#[test]
fn test_http_body_sanitizer_sanitize_body_accepts_boundary_after_malformed_parameter()
 {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static(
        "multipart/form-data; charset; boundary=boundary",
    );
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"username\"\r\n\
\r\n\
alice\r\n\
--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.contains("username=<redacted: multipart text part>"));
}

#[test]
fn test_http_body_sanitizer_ignores_unrequested_multipart_parameter() {
    let sanitizer = HttpBodySanitizer::default();
    let body = b"--b\r\nContent-Disposition: form-data; name=\"password\"; size=6\r\n\r\nsecret\r\n--b--\r\n";
    let content_type = HeaderValue::from_static(
        "multipart/form-data; charset=utf-8; boundary=b",
    );

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert!(result.content().contains("password=<redacted>"));
    assert!(!result.content().contains("secret"));
}

#[test]
fn test_http_body_sanitizer_rejects_valueless_requested_multipart_parameter() {
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);
    let body = b"--b\r\nContent-Disposition: form-data; name=\"note\"; filename\r\nContent-Type: text/plain\r\n\r\nraw-secret\r\n--b--\r\n";
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(result.content(), "<redacted: multipart body>");
    assert_eq!(
        result.status(),
        BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidMultipart,),
    );
    assert!(!result.content().contains("raw-secret"));
}
