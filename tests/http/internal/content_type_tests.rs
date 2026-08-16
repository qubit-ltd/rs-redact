// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for content-type dispatch.

use http::HeaderValue;
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::http::BodyRedactionStatus;
use qubit_redact::formats::http::HttpRedactor;
/// Verifies JSON content types select structured redaction.
#[test]
fn test_content_type_json_selects_structured_redaction() {
    let result = HttpRedactor::default().redact_body(
        BodyCapture::complete(br#"{"password":"raw"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert_eq!(result.status(), BodyRedactionStatus::Structured);
}
