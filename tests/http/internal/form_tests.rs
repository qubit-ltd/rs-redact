// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URL-encoded form redaction.

use http::HeaderValue;
use qubit_redact::http::{
    BodyCapture,
    BodyRedactionStatus,
    HttpRedactor,
};

/// Verifies form values are classified from their field names.
#[test]
fn test_form_masks_password_value() {
    let result = HttpRedactor::default().redact_body(
        BodyCapture::complete(b"password=raw&label=visible"),
        Some(&HeaderValue::from_static(
            "application/x-www-form-urlencoded",
        )),
    );

    assert_eq!(result.status(), BodyRedactionStatus::Structured);
    assert!(!result.to_string().contains("raw"));
    assert!(result.to_string().contains("visible"));
}
