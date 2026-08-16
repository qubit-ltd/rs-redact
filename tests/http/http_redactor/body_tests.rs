// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for body dispatch normalization.

use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::http::BodyRedactionStatus;
use qubit_redact::formats::http::HttpRedactor;
/// Verifies whitespace-surrounded JSON is detected before body dispatch.
#[test]
fn test_body_dispatch_detects_whitespace_surrounded_json() {
    let body = HttpRedactor::default().redact_body(
        BodyCapture::complete(b" \t\r\n{\"password\":\"raw-secret\"}\n "),
        None,
    );

    assert_eq!(body.status(), BodyRedactionStatus::Structured);
    assert!(!body.to_string().contains("raw-secret"));
}
