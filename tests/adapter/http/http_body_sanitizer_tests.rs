// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`HttpBodySanitizer`](qubit_sanitize::HttpBodySanitizer).

use http::HeaderValue;
use proptest::{
    collection,
    prelude::{
        any,
        prop_assert,
        proptest,
    },
};

use qubit_sanitize::{
    FieldSanitizePolicy,
    FieldSanitizer,
    HttpBodySanitizer,
    NameMatchMode,
    SensitivityLevel,
};

#[test]
fn test_http_body_sanitizer_field_sanitizer_accessors() {
    let mut sanitizer = HttpBodySanitizer::default();

    assert!(
        sanitizer
            .field_sanitizer()
            .policy()
            .sensitive_fields()
            .contains("password")
    );
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("customer_id", SensitivityLevel::High);

    let content_type = HeaderValue::from_static("application/json");
    let sanitized = sanitizer.sanitize_body(
        br#"{"customerId":"C-001"}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, r#"{"customerId":"****"}"#);
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_json_fields() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"{"user":"alice","password":"secret","nested":{"token":"abc"}}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(
        sanitized,
        r#"{"nested":{"token":"****"},"password":"<redacted>","user":"alice"}"#
    );
    assert!(!sanitized.contains("secret"));
    assert!(!sanitized.contains("abc"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_keeps_empty_body_empty() {
    let sanitizer = HttpBodySanitizer::default();

    let sanitized =
        sanitizer.sanitize_body(b"", None, NameMatchMode::ExactOrSuffix);
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "");
}

#[test]
fn test_http_body_sanitizer_sanitize_body_preview_renders_empty_preview() {
    let sanitizer = HttpBodySanitizer::default();

    assert_eq!(
        sanitizer
            .sanitize_body_preview(b"", 0, None, NameMatchMode::ExactOrSuffix)
            .into_rendered(),
        "<empty>"
    );
    assert_eq!(
        sanitizer
            .sanitize_body_preview(b"", 10, None, NameMatchMode::ExactOrSuffix)
            .into_rendered(),
        "<empty>...<truncated 10 bytes>",
    );
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_json_arrays() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"[{"token":"abc"},{"nested":{"password":"secret"}}]"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(
        sanitized,
        r#"[{"token":"****"},{"nested":{"password":"<redacted>"}}]"#
    );
    assert!(!sanitized.contains("abc"));
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_sniffs_json_without_content_type() {
    let sanitizer = HttpBodySanitizer::default();

    let sanitized = sanitizer.sanitize_body(
        br#" {"accessToken":"secret-access"}"#,
        None,
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, r#"{"accessToken":"****"}"#);
    assert!(!sanitized.contains("secret-access"));
}

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
fn test_http_body_sanitizer_exact_mode_keeps_prefixed_json_field() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"{"openaiApiKey":"secret-access","token":"abcdef"}"#,
        Some(&content_type),
        NameMatchMode::Exact,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(
        sanitized,
        r#"{"openaiApiKey":"secret-access","token":"****"}"#,
    );
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_invalid_json() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"{"password":"secret""#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: invalid JSON>");
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_preview_redacts_truncated_json() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");
    let body = br#"{"password":"secret","user":"alice","tail":"long"}"#;
    let prefix = &body[..20];

    let sanitized = sanitizer.sanitize_body_preview(
        prefix,
        body.len(),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(
        sanitized
            .starts_with("<redacted: invalid or truncated JSON>...<truncated ")
    );
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_ndjson_fields() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/x-ndjson");

    let sanitized = sanitizer.sanitize_body(
        br#"{"token":"abc","id":1}

{"id":2}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "{\"id\":1,\"token\":\"****\"}\n\n{\"id\":2}");
    assert!(!sanitized.contains("abc"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_preview_redacts_truncated_ndjson() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/x-ndjson");
    let body = br#"{"token":"abc","id":1}"#;
    let prefix = &body[..10];

    let sanitized = sanitizer.sanitize_body_preview(
        prefix,
        body.len(),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(
        sanitized.starts_with(
            "<redacted: invalid or truncated NDJSON>...<truncated "
        )
    );
    assert!(!sanitized.contains("abc"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_form_fields() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("application/x-www-form-urlencoded");

    let sanitized = sanitizer.sanitize_body(
        b"username=alice&password=secret&city=Shanghai",
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(
        sanitized,
        "username=alice&password=%3Credacted%3E&city=Shanghai"
    );
    assert!(!sanitized.contains("secret"));
}

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

    assert_eq!(sanitized, "<multipart>\n</multipart>");
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
        body.len(),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert!(sanitized.starts_with("<redacted: multipart body>...<truncated "));
    assert!(!sanitized.contains("secret-password-in-truncated-body"));
    assert!(!sanitized.contains("boundary"));
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

#[test]
fn test_http_body_sanitizer_sanitize_body_uses_custom_policy() {
    let mut policy = FieldSanitizePolicy::empty();
    policy
        .sensitive_fields_mut()
        .insert("customer_id", SensitivityLevel::High);
    let sanitizer = HttpBodySanitizer::new(FieldSanitizer::new(policy));
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"{"customer_id":"C-001","password":"kept"}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, r#"{"customer_id":"****","password":"kept"}"#);
}

#[test]
fn test_http_body_sanitizer_sanitize_body_preview_adds_text_truncation_suffix()
{
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("text/plain");
    let body = b"hello world";
    let prefix = &body[..5];

    let sanitized = sanitizer.sanitize_body_preview(
        prefix,
        body.len(),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: text body>...<truncated 6 bytes>",);
}

#[test]
fn test_http_body_sanitizer_sanitize_body_renders_binary_body() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/octet-stream");

    let sanitized = sanitizer.sanitize_body(
        b"\xff\x00\x01",
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<binary 3 bytes>");
}

proptest! {
    #[test]
    fn test_http_body_sanitizer_proptest_never_leaks_structured_sensitive_value(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let sanitizer = HttpBodySanitizer::default();
        let cases = [
            (
                format!(r#"{{"password":"{secret}"}}"#),
                HeaderValue::from_static("application/json"),
            ),
            (
                format!("{{\"password\":\"{secret}\"}}\n"),
                HeaderValue::from_static("application/x-ndjson"),
            ),
            (
                format!("password={secret}"),
                HeaderValue::from_static(
                    "application/x-www-form-urlencoded",
                ),
            ),
            (
                format!(
                    "--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{secret}\r\n--boundary--\r\n",
                ),
                HeaderValue::from_static(
                    "multipart/form-data; boundary=boundary",
                ),
            ),
        ];

        for (body, content_type) in cases {
            let sanitized = sanitizer.sanitize_body(
                body.as_bytes(),
                Some(&content_type),
                NameMatchMode::ExactOrSuffix,
            );
            let sanitized = sanitized.into_rendered();
            prop_assert!(!sanitized.contains(&secret));
        }
    }

    #[test]
    fn test_http_body_sanitizer_proptest_handles_arbitrary_body(
        body in collection::vec(any::<u8>(), 0..512),
    ) {
        let sanitizer = HttpBodySanitizer::default();
        let content_types = [
            None,
            Some(HeaderValue::from_static("application/json")),
            Some(HeaderValue::from_static("application/x-ndjson")),
            Some(HeaderValue::from_static("application/x-www-form-urlencoded")),
            Some(HeaderValue::from_static("multipart/form-data; boundary=boundary")),
            Some(HeaderValue::from_static("text/plain")),
            Some(HeaderValue::from_static("application/octet-stream")),
        ];

        for content_type in &content_types {
            let _ = sanitizer.sanitize_body(
                &body,
                content_type.as_ref(),
                NameMatchMode::ExactOrSuffix,
            );
        }
    }
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_unsupported_utf8_body() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/xml");

    let sanitized = sanitizer.sanitize_body(
        b"<password>secret</password>",
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: unsupported HTTP body>");
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_utf8_body_without_content_type()
 {
    let sanitizer = HttpBodySanitizer::default();

    let sanitized = sanitizer.sanitize_body(
        b"password=secret",
        None,
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: unsupported HTTP body>");
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_constructed_from_field_sanitizer() {
    let sanitizer = HttpBodySanitizer::new(FieldSanitizer::default());
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"{"token":"abcdef"}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, r#"{"token":"****"}"#);
}
