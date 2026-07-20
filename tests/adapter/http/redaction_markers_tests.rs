// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for rendered HTTP body redaction markers.

use http::HeaderValue;

use qubit_redact::{
    BodyRedactionReason,
    BodySanitizationStatus,
    BodySourceLength,
    HttpBodySanitizer,
    NameMatchMode,
};

#[test]
fn test_unknown_truncated_structured_previews_use_generic_suffix_and_reason() {
    let sanitizer = HttpBodySanitizer::default();
    let cases = [
        (
            HeaderValue::from_static("application/json"),
            br#"{"password":"secret""#.as_slice(),
            BodyRedactionReason::InvalidOrTruncatedJson,
            "<redacted: invalid or truncated JSON>...<truncated>",
        ),
        (
            HeaderValue::from_static("application/x-ndjson"),
            br#"{"token":"secret""#.as_slice(),
            BodyRedactionReason::InvalidOrTruncatedNdjson,
            "<redacted: invalid or truncated NDJSON>...<truncated>",
        ),
        (
            HeaderValue::from_static("application/x-www-form-urlencoded"),
            b"password=secret%".as_slice(),
            BodyRedactionReason::InvalidOrTruncatedFormUrlEncoded,
            "<redacted: invalid or truncated URL-encoded form>...<truncated>",
        ),
        (
            HeaderValue::from_static("multipart/form-data; boundary=b"),
            b"--b\r\n".as_slice(),
            BodyRedactionReason::TruncatedMultipart,
            "<redacted: multipart body>...<truncated>",
        ),
    ];

    for (content_type, prefix, reason, expected) in cases {
        let result = sanitizer.sanitize_body_preview(
            prefix,
            BodySourceLength::UnknownTruncated,
            Some(&content_type),
            NameMatchMode::ExactOrSuffix,
        );

        assert_eq!(result.status(), BodySanitizationStatus::Redacted(reason),);
        assert_eq!(result.source_len(), None);
        assert_eq!(result.truncated_bytes(), None);
        assert!(result.is_truncated());
        assert_eq!(result.into_rendered(), expected);
    }
}

#[test]
fn test_body_sanitization_complete_result_has_no_truncation_suffix() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");
    let body = br#"{"password":"secret"}"#;

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(result.status(), BodySanitizationStatus::Sanitized);
    assert_eq!(result.captured_len(), body.len());
    assert_eq!(result.source_len(), Some(body.len()));
    assert_eq!(result.truncated_bytes(), Some(0));
    assert!(!result.is_truncated());
    assert_eq!(result.raw_content(), r#"{"password":"<redacted>"}"#);
    assert_eq!(result.rendered(), result.raw_content());

    let consumed = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    assert_eq!(consumed.into_rendered(), r#"{"password":"<redacted>"}"#);
}

#[test]
fn test_body_sanitization_into_raw_content_omits_truncation_suffix() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");
    let prefix = br#"{"password":"secret"#;

    let result = sanitizer.sanitize_body_preview(
        prefix,
        BodySourceLength::Known(40),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(
        result.into_raw_content(),
        "<redacted: invalid or truncated JSON>",
    );
}

#[test]
fn test_http_body_sanitizer_reports_redaction_and_binary_statuses() {
    let sanitizer = HttpBodySanitizer::default();
    let json = HeaderValue::from_static("application/json");
    let ndjson = HeaderValue::from_static("application/x-ndjson");
    let multipart =
        HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let text = HeaderValue::from_static("text/plain");
    let invalid_content_type = HeaderValue::from_bytes(&[0xff])
        .expect("non-UTF-8 header value should be valid");

    let cases = [
        (
            sanitizer.sanitize_body(
                b"{invalid",
                Some(&json),
                NameMatchMode::Exact,
            ),
            BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidJson),
        ),
        (
            sanitizer.sanitize_body(
                b"{invalid\n",
                Some(&ndjson),
                NameMatchMode::Exact,
            ),
            BodySanitizationStatus::Redacted(
                BodyRedactionReason::InvalidNdjson,
            ),
        ),
        (
            sanitizer.sanitize_body_preview(
                b"{invalid\n",
                BodySourceLength::Known(40),
                Some(&ndjson),
                NameMatchMode::Exact,
            ),
            BodySanitizationStatus::Redacted(
                BodyRedactionReason::InvalidOrTruncatedNdjson,
            ),
        ),
        (
            sanitizer.sanitize_body(
                b"body",
                Some(&invalid_content_type),
                NameMatchMode::Exact,
            ),
            BodySanitizationStatus::Redacted(
                BodyRedactionReason::InvalidContentType,
            ),
        ),
        (
            sanitizer.sanitize_body(b"body", None, NameMatchMode::Exact),
            BodySanitizationStatus::Redacted(
                BodyRedactionReason::UnsupportedMediaType,
            ),
        ),
        (
            sanitizer.sanitize_body(b"body", Some(&text), NameMatchMode::Exact),
            BodySanitizationStatus::Redacted(BodyRedactionReason::OpaqueText),
        ),
        (
            sanitizer.sanitize_body(
                b"invalid multipart",
                Some(&multipart),
                NameMatchMode::Exact,
            ),
            BodySanitizationStatus::Redacted(
                BodyRedactionReason::InvalidMultipart,
            ),
        ),
        (
            sanitizer.sanitize_body_preview(
                b"--boundary\r\n",
                BodySourceLength::Known(40),
                Some(&multipart),
                NameMatchMode::Exact,
            ),
            BodySanitizationStatus::Redacted(
                BodyRedactionReason::TruncatedMultipart,
            ),
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
