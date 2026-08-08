// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for parser output propagated through HTTP body redaction.

use http::HeaderValue;
use qubit_redact::http::BodyCapture;
use qubit_redact::http::BodyRedactionStatus;
use qubit_redact::http::HttpRedactor;
/// Verifies structured parser output retains its status through final
/// rendering.
#[test]
fn test_parsed_body_preserves_structured_status() {
    let result = HttpRedactor::default().redact_body(
        BodyCapture::complete(br#"{"password":"raw-secret","mode":"visible"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert_eq!(result.status(), BodyRedactionStatus::Structured);
    assert!(!result.to_string().contains("raw-secret"));
}
