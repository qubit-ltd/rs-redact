// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for public multipart HTTP body sanitization behavior.

use http::HeaderValue;

use qubit_sanitize::{
    BodySanitizationStatus,
    BodySourceLength,
    HttpBodySanitizer,
    NameMatchMode,
    UnkeyedJsonValuePolicy,
};

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_multipart_fields() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"username\"\r\n\
\r\n\
alice\r\n\
--boundary\r\n\
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

    assert!(sanitized.contains("username=<redacted: multipart text part>"));
    assert!(sanitized.contains("password=<redacted>"));
    assert!(!sanitized.contains("secret-password"));
    assert!(!sanitized.contains("boundary"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_multipart_mixed_fields() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/mixed; boundary=boundary");
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

    assert!(sanitized.contains("password=<redacted>"));
    assert!(!sanitized.contains("secret-password"));
    assert!(!sanitized.contains("boundary"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_multipart_json_part() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = br#"--boundary
Content-Disposition: form-data; name="metadata"
Content-Type: application/json

{"token":"secret-token","visible":"ok"}
--boundary--
"#;

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.contains(r#"metadata={"token":"****","visible":"ok"}"#));
    assert!(!sanitized.contains("secret-token"));
    assert!(!sanitized.contains("boundary"));
}

#[test]
fn test_http_body_sanitizer_reports_multipart_json_pass_through() {
    let sanitizer = HttpBodySanitizer::default()
        .with_unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough);
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = br#"--boundary
Content-Disposition: form-data; name="metadata"
Content-Type: application/json

["diagnostic"]
--boundary--
"#;

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert!(result.content().contains(r#"metadata=["diagnostic"]"#));
    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_multipart_text_part() {
    let sanitizer = HttpBodySanitizer::default();
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
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.contains("description=<redacted: multipart text part>"));
    assert!(!sanitized.contains("plain text value"));
    assert!(!sanitized.contains("boundary"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_invalid_multipart_json_part()
{
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"metadata\"\r\n\
Content-Type: application/json\r\n\
\r\n\
{\"token\":\"secret-token\"\r\n\
--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.contains("metadata=<redacted: multipart part>"));
    assert!(!sanitized.contains("secret-token"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_invalid_multipart_ndjson_part()
 {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"events\"\r\n\
Content-Type: application/x-ndjson\r\n\
\r\n\
{\"token\":\"secret-token\"\n\
--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.contains("events=<redacted: multipart part>"));
    assert!(!sanitized.contains("secret-token"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_multipart_form_part() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"payload\"\r\n\
Content-Type: application/x-www-form-urlencoded\r\n\
\r\n\
username=alice&password=secret-password\r\n\
--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(
        sanitized.contains("payload=username=alice&password=%3Credacted%3E")
    );
    assert!(!sanitized.contains("secret-password"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_unknown_multipart_part_content_type()
 {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"payload\"\r\n\
Content-Type: application/octet-stream\r\n\
\r\n\
secret-binary-looking-content\r\n\
--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.contains("payload=<redacted: multipart part>"));
    assert!(!sanitized.contains("secret-binary-looking-content"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_handles_empty_multipart_body() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\r\n\r\n--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, r"<multipart>\n</multipart>");
}

#[test]
fn test_http_body_sanitizer_summarizes_non_utf8_multipart_file_part() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"payload.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nbinary-\xff-data\r\n--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret\r\n--boundary--\r\n\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(
        sanitized.content(),
        "<multipart>\nupload=<redacted: file part>\npassword=<redacted>\n</multipart>",
    );
    assert!(!sanitized.content().contains("binary"));
    assert!(!sanitized.content().contains("secret"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_non_utf8_multipart() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body =
        b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret-\xff\r\n--boundary--\r\n";

    let sanitized = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: multipart body>");
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_preview_redacts_truncated_multipart()
{
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\n\
Content-Disposition: form-data; name=\"password\"\r\n\
\r\n\
secret-password-in-truncated-body\r\n\
--boundary--\r\n";
    let prefix = &body[..72];

    let sanitized = sanitizer.sanitize_body_preview(
        prefix,
        BodySourceLength::Known(body.len()),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.starts_with("<redacted: multipart body>...<truncated "));
    assert!(!sanitized.contains("secret-password-in-truncated-body"));
    assert!(!sanitized.contains("boundary"));
}
