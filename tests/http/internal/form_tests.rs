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
