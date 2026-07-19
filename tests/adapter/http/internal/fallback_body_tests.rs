// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for fallback HTTP body sanitization through the public API.

use http::HeaderValue;

use qubit_sanitize::{
    BodyRedactionReason,
    BodySanitizationStatus,
    BodySourceLength,
    HttpBodySanitizer,
    NameMatchMode,
    TextBodyPolicy,
};

#[test]
fn test_fallback_body_sanitizer_applies_opaque_text_policy() {
    let content_type = HeaderValue::from_static("text/plain");
    let sanitizer = HttpBodySanitizer::default()
        .with_text_body_policy(TextBodyPolicy::PassThrough);

    let result = sanitizer.sanitize_body(
        b"diagnostic text",
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(result.content(), "diagnostic text");
    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
}

#[test]
fn test_fallback_body_sanitizer_preserves_unknown_binary_length() {
    let sanitizer = HttpBodySanitizer::default();

    let result = sanitizer.sanitize_body_preview(
        &[0xFF, 0x00],
        BodySourceLength::UnknownTruncated,
        None,
        NameMatchMode::Exact,
    );

    assert_eq!(result.content(), "<binary more than 2 bytes>");
    assert_eq!(result.status(), BodySanitizationStatus::Binary);
    assert_ne!(
        result.status(),
        BodySanitizationStatus::Redacted(
            BodyRedactionReason::UnsupportedMediaType,
        ),
    );
}
