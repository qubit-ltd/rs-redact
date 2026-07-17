// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internal multipart part-metadata handling behavior.

use http::HeaderValue;

use qubit_sanitize::{
    HttpBodySanitizer,
    NameMatchMode,
    SensitivityLevel,
    TextBodyPolicy,
};

#[test]
fn test_http_body_sanitizer_redacts_duplicate_multipart_headers() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    for body in [
        "--boundary\r\nContent-Disposition: form-data; name=note\r\nContent-Disposition: form-data; name=password\r\n\r\nsecret\r\n--boundary--\r\n",
        "--boundary\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\nContent-Type: application/json\r\n\r\nsecret\r\n--boundary--\r\n",
    ] {
        let result = sanitizer.sanitize_body(
            body.as_bytes(),
            Some(&content_type),
            NameMatchMode::ExactOrSuffix,
        );

        assert_eq!(result.to_string(), "<redacted: multipart body>");
    }
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_multipart_file_part() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"alice\\\";private-report.txt\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
password=secret-in-file\r\n\
--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.contains("upload=<redacted: file part>"));
    assert!(!sanitized.contains("alice"));
    assert!(!sanitized.contains("secret-in-file"));
    assert!(!sanitized.contains("private-report.txt"));
}

#[test]
fn test_http_body_sanitizer_redacts_file_part_before_field_policy() {
    let mut sanitizer = HttpBodySanitizer::default();
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("attachment", SensitivityLevel::Low);
    let body = b"--b\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"secret.txt\"\r\nContent-Type: text/plain\r\n\r\nraw-file-secret\r\n--b--\r\n";
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert!(result.content().contains("<redacted: file part>"));
    assert!(!result.content().contains("raw-file-secret"));
}

#[test]
fn test_http_body_sanitizer_treats_blank_multipart_name_as_unnamed() {
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);
    let body = b"--b\r\nContent-Disposition: form-data; name=\"   \"\r\nContent-Type: text/plain\r\n\r\nraw-secret\r\n--b--\r\n";
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert!(
        result
            .content()
            .contains("<unnamed>=<redacted: multipart part>")
    );
    assert!(!result.content().contains("raw-secret"));
}

#[test]
fn test_http_body_sanitizer_redacts_extended_filename_part() {
    let sanitizer = HttpBodySanitizer::default();
    let body = b"--b\r\nContent-Disposition: form-data; name=\"attachment\"; filename*=UTF-8''secret.txt\r\nContent-Type: text/plain\r\n\r\nraw-file-secret\r\n--b--\r\n";
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert!(result.content().contains("<redacted: file part>"));
    assert!(!result.content().contains("raw-file-secret"));
}

#[test]
fn test_http_body_sanitizer_escapes_multipart_field_name_controls() {
    let mut sanitizer = HttpBodySanitizer::default();
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("note\u{1b}[31m", SensitivityLevel::High);
    let body =
        b"--b\r\nContent-Disposition: form-data; name=\"note\x1b[31m\"\r\n\r\nsecret\r\n--b--\r\n";
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=b");

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert!(result.content().contains(r#"note\u{1b}[31m="#));
    assert!(!result.content().contains('\u{1b}'));
    assert!(!result.content().contains("secret"));
}
