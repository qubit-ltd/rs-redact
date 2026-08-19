// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for content-type dispatch.

use http::HeaderValue;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

use crate::http::support::redaction::redact_body;
/// Verifies JSON content types select structured redaction.
#[test]
fn test_content_type_json_selects_structured_redaction() {
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(br#"{"password":"raw"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert!(!rendered.contains("raw"));
}
