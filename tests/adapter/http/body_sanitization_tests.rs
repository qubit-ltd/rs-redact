// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodySanitization`](qubit_redact::BodySanitization).

use http::HeaderValue;

use qubit_redact::{
    BodyRedactionReason,
    BodySanitization,
    BodySanitizationStatus,
    BodySourceLength,
    HttpBodySanitizer,
    NameMatchMode,
    TextBodyPolicy,
};

#[test]
fn test_body_sanitization_types_are_public() {
    let status = BodySanitizationStatus::Redacted(
        BodyRedactionReason::InvalidOrTruncatedJson,
    );

    assert_eq!(
        status,
        BodySanitizationStatus::Redacted(
            BodyRedactionReason::InvalidOrTruncatedJson,
        ),
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
        BodySourceLength::Known(40),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(
        result.status(),
        BodySanitizationStatus::Redacted(
            BodyRedactionReason::InvalidOrTruncatedJson,
        ),
    );
    assert_eq!(result.captured_len(), prefix.len());
    assert_eq!(result.source_len(), Some(40));
    assert_eq!(result.truncated_bytes(), Some(40 - prefix.len()));
    assert!(result.is_truncated());
    assert!(!result.raw_content().contains("secret"));
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
fn test_http_body_sanitizer_reports_top_level_text_as_passed_through() {
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type = HeaderValue::from_static("text/plain");

    let result = sanitizer.sanitize_body(
        b"visible text",
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
}

#[test]
fn test_body_sanitization_rendering_escapes_log_control_characters() {
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type = HeaderValue::from_static("text/plain");
    let body = b"first\nsecond\t\x1b[31m";

    let result = sanitizer.sanitize_body(
        body,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(result.raw_content().as_bytes(), body);
    assert_eq!(result.clone().into_raw_content().as_bytes(), body);
    assert_eq!(result.escaped_content(), r"first\nsecond\t\u{1b}[31m");
    assert_eq!(
        result.clone().into_escaped_content(),
        r"first\nsecond\t\u{1b}[31m",
    );
    assert_eq!(result.to_string(), r"first\nsecond\t\u{1b}[31m");
    assert_eq!(result.rendered(), r"first\nsecond\t\u{1b}[31m");
    assert_eq!(result.into_rendered(), r"first\nsecond\t\u{1b}[31m");
}

#[test]
fn test_body_sanitization_rendering_escapes_unicode_log_controls() {
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);
    let content_type = HeaderValue::from_static("text/plain");
    let body = "first\u{2028}second\u{202e}tail";

    let result = sanitizer.sanitize_body(
        body.as_bytes(),
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(result.raw_content(), body);
    assert_eq!(result.clone().into_raw_content(), body);
    assert_eq!(result.escaped_content(), r"first\u{2028}second\u{202e}tail",);
    assert_eq!(
        result.clone().into_escaped_content(),
        r"first\u{2028}second\u{202e}tail",
    );
    assert_eq!(result.to_string(), r"first\u{2028}second\u{202e}tail");
    assert_eq!(result.rendered(), r"first\u{2028}second\u{202e}tail");
    assert_eq!(result.into_rendered(), r"first\u{2028}second\u{202e}tail");
}
