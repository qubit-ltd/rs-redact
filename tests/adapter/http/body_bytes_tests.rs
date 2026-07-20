// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for HTTP body byte-input classification.

use qubit_redact::{
    BodySourceLength,
    HttpBodySanitizer,
    NameMatchMode,
};

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
            .sanitize_body_preview(
                b"",
                BodySourceLength::Known(0),
                None,
                NameMatchMode::ExactOrSuffix,
            )
            .into_rendered(),
        "<empty>"
    );
    assert_eq!(
        sanitizer
            .sanitize_body_preview(
                b"",
                BodySourceLength::Known(10),
                None,
                NameMatchMode::ExactOrSuffix,
            )
            .into_rendered(),
        "<empty>...<truncated 10 bytes>",
    );
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
