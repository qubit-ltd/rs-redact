// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodySanitization`](qubit_sanitize::BodySanitization).

use http::HeaderValue;

use qubit_sanitize::{
    BodyRedactionReason, BodySanitization, BodySanitizationStatus, HttpBodySanitizer,
    NameMatchMode, TextBodyPolicy,
};

#[test]
fn test_body_sanitization_types_are_public() {
    let status = BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidOrTruncatedJson);

    assert_eq!(
        status,
        BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidOrTruncatedJson,),
    );
    let _: Option<BodySanitization> = None;
}

#[test]
fn test_http_body_sanitizer_preview_returns_structured_redaction_metadata() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");
    let prefix = br#"{"password":"secret"#;

    let result = sanitizer.sanitize_body_preview(
        prefix,
        40,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(
        result.status(),
        BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidOrTruncatedJson,),
    );
    assert_eq!(result.captured_len(), prefix.len());
    assert_eq!(result.source_len(), 40);
    assert_eq!(result.truncated_bytes(), 40 - prefix.len());
    assert!(result.is_truncated());
    assert!(!result.content().contains("secret"));
    assert_eq!(
        result.to_string(),
        format!(
            "<redacted: invalid or truncated JSON>...<truncated {} bytes>",
            40 - prefix.len(),
        ),
    );
    assert_eq!(result.rendered(), result.to_string());
}

#[test]
fn test_body_sanitization_complete_result_has_no_truncation_suffix() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");
    let body = br#"{"password":"secret"}"#;

    let result = sanitizer.sanitize_body(body, Some(&content_type), NameMatchMode::ExactOrSuffix);

    assert_eq!(result.status(), BodySanitizationStatus::Sanitized);
    assert_eq!(result.captured_len(), body.len());
    assert_eq!(result.source_len(), body.len());
    assert_eq!(result.truncated_bytes(), 0);
    assert!(!result.is_truncated());
    assert_eq!(result.content(), r#"{"password":"<redacted>"}"#);
    assert_eq!(result.rendered(), result.content());

    let consumed = sanitizer.sanitize_body(body, Some(&content_type), NameMatchMode::ExactOrSuffix);
    assert_eq!(consumed.into_rendered(), r#"{"password":"<redacted>"}"#);
}

#[test]
fn test_http_body_sanitizer_reports_top_level_text_as_passed_through() {
    let sanitizer = HttpBodySanitizer::default().with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type = HeaderValue::from_static("text/plain");

    let result =
        sanitizer.sanitize_body(b"visible text", Some(&content_type), NameMatchMode::Exact);

    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
}

#[test]
fn test_http_body_sanitizer_reports_multipart_text_as_passed_through() {
    let sanitizer = HttpBodySanitizer::default().with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type = HeaderValue::from_static("multipart/form-data; boundary=b");
    let body = b"--b\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain\r\n\r\nvisible text\r\n--b--\r\n";

    let result = sanitizer.sanitize_body(body, Some(&content_type), NameMatchMode::Exact);

    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
}

#[test]
fn test_http_body_sanitizer_reports_mixed_multipart_as_passed_through() {
    let sanitizer = HttpBodySanitizer::default().with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type = HeaderValue::from_static("multipart/form-data; boundary=b");
    let body = b"--b\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain\r\n\r\nvisible text\r\n--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret value\r\n--b--\r\n";

    let result = sanitizer.sanitize_body(body, Some(&content_type), NameMatchMode::Exact);

    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
    assert!(result.content().contains("note=visible text"));
    assert!(result.content().contains("password=<redacted>"));
    assert!(!result.content().contains("secret value"));
}

#[test]
fn test_body_sanitization_into_content_omits_truncation_suffix() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");
    let prefix = br#"{"password":"secret"#;

    let result = sanitizer.sanitize_body_preview(
        prefix,
        40,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(
        result.into_content(),
        "<redacted: invalid or truncated JSON>",
    );
}

#[test]
fn test_body_sanitization_empty_preview_keeps_source_metadata() {
    let sanitizer = HttpBodySanitizer::default();

    let result = sanitizer.sanitize_body_preview(b"", 10, None, NameMatchMode::ExactOrSuffix);

    assert_eq!(result.status(), BodySanitizationStatus::Empty);
    assert_eq!(result.content(), "<empty>");
    assert_eq!(result.captured_len(), 0);
    assert_eq!(result.source_len(), 10);
    assert_eq!(result.to_string(), "<empty>...<truncated 10 bytes>");
}

#[test]
fn test_http_body_sanitizer_reports_redaction_and_binary_statuses() {
    let sanitizer = HttpBodySanitizer::default();
    let json = HeaderValue::from_static("application/json");
    let ndjson = HeaderValue::from_static("application/x-ndjson");
    let multipart = HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let text = HeaderValue::from_static("text/plain");
    let invalid_content_type =
        HeaderValue::from_bytes(&[0xff]).expect("non-UTF-8 header value should be valid");

    let cases = [
        (
            sanitizer.sanitize_body(b"{invalid", Some(&json), NameMatchMode::Exact),
            BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidJson),
        ),
        (
            sanitizer.sanitize_body(b"{invalid\n", Some(&ndjson), NameMatchMode::Exact),
            BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidNdjson),
        ),
        (
            sanitizer.sanitize_body_preview(b"{invalid\n", 40, Some(&ndjson), NameMatchMode::Exact),
            BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidOrTruncatedNdjson),
        ),
        (
            sanitizer.sanitize_body(b"body", Some(&invalid_content_type), NameMatchMode::Exact),
            BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidContentType),
        ),
        (
            sanitizer.sanitize_body(b"body", None, NameMatchMode::Exact),
            BodySanitizationStatus::Redacted(BodyRedactionReason::UnsupportedMediaType),
        ),
        (
            sanitizer.sanitize_body(b"body", Some(&text), NameMatchMode::Exact),
            BodySanitizationStatus::Redacted(BodyRedactionReason::OpaqueText),
        ),
        (
            sanitizer.sanitize_body(b"invalid multipart", Some(&multipart), NameMatchMode::Exact),
            BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidMultipart),
        ),
        (
            sanitizer.sanitize_body_preview(
                b"--boundary\r\n",
                40,
                Some(&multipart),
                NameMatchMode::Exact,
            ),
            BodySanitizationStatus::Redacted(BodyRedactionReason::TruncatedMultipart),
        ),
        (
            sanitizer.sanitize_body(&[0xff], None, NameMatchMode::Exact),
            BodySanitizationStatus::Binary,
        ),
    ];

    for (result, expected_status) in cases {
        assert_eq!(result.status(), expected_status);
    }
}
