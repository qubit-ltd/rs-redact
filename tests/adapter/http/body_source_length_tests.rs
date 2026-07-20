// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for HTTP body source-length metadata.

use qubit_redact::{
    BodySanitizationStatus,
    BodySourceLength,
    HttpBodySanitizer,
    NameMatchMode,
};

#[test]
fn test_body_sanitization_unknown_truncated_source_has_no_exact_length() {
    let result = HttpBodySanitizer::default().sanitize_body_preview(
        b"prefix",
        BodySourceLength::UnknownTruncated,
        None,
        NameMatchMode::Exact,
    );

    assert_eq!(result.source_len(), None);
    assert_eq!(result.truncated_bytes(), None);
    assert!(result.is_truncated());
    assert_eq!(
        result.to_string(),
        "<redacted: unsupported HTTP body>...<truncated>",
    );
    assert_eq!(
        result.clone().into_rendered(),
        "<redacted: unsupported HTTP body>...<truncated>",
    );
}

#[test]
fn test_body_sanitization_empty_preview_keeps_source_metadata() {
    let sanitizer = HttpBodySanitizer::default();

    let result = sanitizer.sanitize_body_preview(
        b"",
        BodySourceLength::Known(10),
        None,
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(result.status(), BodySanitizationStatus::Empty);
    assert_eq!(result.raw_content(), "<empty>");
    assert_eq!(result.captured_len(), 0);
    assert_eq!(result.source_len(), Some(10));
    assert_eq!(result.to_string(), "<empty>...<truncated 10 bytes>");
}

#[test]
fn test_body_sanitization_clamps_inconsistent_known_source_length() {
    let sanitizer = HttpBodySanitizer::default();
    let body = b"visible";

    let result = sanitizer.sanitize_body_preview(
        body,
        BodySourceLength::Known(1),
        None,
        NameMatchMode::ExactOrSuffix,
    );

    assert_eq!(result.source_len(), Some(body.len()));
    assert_eq!(result.captured_len(), body.len());
    assert_eq!(result.truncated_bytes(), Some(0));
    assert!(!result.is_truncated());
}
