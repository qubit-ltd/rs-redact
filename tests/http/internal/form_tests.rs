// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URL-encoded form redaction.

use http::HeaderValue;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

use crate::http::support::redaction::redact_body;

/// Verifies form values are classified from their field names.
#[test]
fn test_form_masks_password_value() {
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(b"password=raw&label=visible"),
        Some(&HeaderValue::from_static("application/x-www-form-urlencoded")),
    );

    assert!(!rendered.contains("raw"));
    assert!(rendered.contains("visible"));
}

/// Keeps ordinary UTF-8, empty, and plus-separated form components valid.
#[test]
fn test_plain_and_escaped_form_components_remain_valid() {
    let output = Redactor::standard().redact_http_body_with_content_type_text(
        BodyCapture::complete(b"region=us&empty=&label=%E9%9B%AA&phrase=hello+world&password=raw%2Bsecret"),
        Some("application/x-www-form-urlencoded"),
    );
    let text = output.text().as_str();

    assert!(text.contains("region=us"), "ordinary component should remain: {text}");
    assert!(text.contains("empty="), "empty value should remain: {text}");
    assert!(text.contains("hello+world"), "form plus should remain valid: {text}");
    assert!(!text.contains("raw"), "secret value should remain masked: {text}");
}

/// Rejects malformed percent escapes and invalid UTF-8 in raw form bytes.
#[test]
fn test_invalid_form_component_remains_fail_closed() {
    let output = Redactor::standard().redact_http_body_with_content_type_text(
        BodyCapture::complete(b"label=\xFF&password=raw-secret"),
        Some("application/x-www-form-urlencoded"),
    );

    assert!(
        output
            .summary()
            .reasons()
            .contains(qubit_redact::RedactionReason::InvalidForm)
    );
    assert!(!output.text().as_str().contains("raw-secret"));
}
