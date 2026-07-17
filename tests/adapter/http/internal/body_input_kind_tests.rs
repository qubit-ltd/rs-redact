// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internal HTTP body input-kind classification behavior.

use http::HeaderValue;

use qubit_sanitize::{
    BodyRedactionReason,
    BodySanitizationStatus,
    BodySourceLength,
    HttpBodySanitizer,
    NameMatchMode,
};

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
        BodySourceLength::Known(body.len()),
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
fn test_http_body_sanitizer_sanitize_body_preview_redacts_truncated_ndjson() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/x-ndjson");
    let body = br#"{"token":"abc","id":1}"#;
    let prefix = &body[..10];

    let sanitized = sanitizer.sanitize_body_preview(
        prefix,
        BodySourceLength::Known(body.len()),
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
fn test_http_body_sanitizer_complete_preview_reports_invalid_json() {
    let content_type = HeaderValue::from_static("application/json");
    let body = br#"{"password":"secret""#;
    let result = HttpBodySanitizer::default().sanitize_body_preview(
        body,
        BodySourceLength::Known(body.len()),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(
        result.status(),
        BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidJson),
    );
    assert_eq!(result.source_len(), Some(body.len()));
    assert_eq!(result.truncated_bytes(), Some(0));
    assert!(!result.is_truncated());
}

#[test]
fn test_http_body_sanitizer_redacts_invalid_urlencoded_form() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("application/x-www-form-urlencoded");

    for body in [
        b"%FFpassword=secret".as_slice(),
        b"%ZZpassword=secret",
        b"password=secret%",
    ] {
        let result = sanitizer.sanitize_body(
            body,
            Some(&content_type),
            NameMatchMode::ExactOrSuffix,
        );
        assert_eq!(
            result.status(),
            BodySanitizationStatus::Redacted(
                BodyRedactionReason::InvalidFormUrlEncoded,
            ),
        );
        assert_eq!(result.content(), "<redacted: invalid URL-encoded form>");
        assert!(!result.content().contains("secret"));
    }
}

#[test]
fn test_http_body_sanitizer_redacts_invalid_or_truncated_urlencoded_preview() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("application/x-www-form-urlencoded");
    let prefix = b"password=secret%";

    let result = sanitizer.sanitize_body_preview(
        prefix,
        BodySourceLength::Known(prefix.len() + 20),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(
        result.status(),
        BodySanitizationStatus::Redacted(
            BodyRedactionReason::InvalidOrTruncatedFormUrlEncoded,
        ),
    );
    assert_eq!(
        result.content(),
        "<redacted: invalid or truncated URL-encoded form>",
    );
    assert!(!result.content().contains("secret"));
}
