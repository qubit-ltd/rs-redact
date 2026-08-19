// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for body dispatch normalization.

use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

use crate::http::support::redaction::redact_body;
/// Verifies whitespace-surrounded JSON is detected before body dispatch.
#[test]
fn test_body_dispatch_detects_whitespace_surrounded_json() {
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(b" \t\r\n{\"password\":\"raw-secret\"}\n "),
        None,
    );

    assert!(!rendered.contains("raw-secret"));
}
