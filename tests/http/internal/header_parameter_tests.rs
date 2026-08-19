// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for multipart header parameter parsing.

use http::HeaderValue;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

use crate::http::support::redaction::redact_body;
/// Verifies malformed multipart parameters fail closed.
#[test]
fn test_header_parameter_malformed_multipart_hides_body() {
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(b"--x\r\ncontent\r\n--x--\r\n"),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=x")),
    );

    assert!(!rendered.contains("content"));
}
