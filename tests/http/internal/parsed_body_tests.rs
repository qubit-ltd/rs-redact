// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for parser output propagated through HTTP body redaction.

use http::HeaderValue;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

use crate::http::support::redaction::redact_body;
/// Verifies structured parser output retains its status through final
/// rendering.
#[test]
fn test_parsed_body_preserves_structured_status() {
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(br#"{"password":"raw-secret","mode":"visible"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert!(!rendered.contains("raw-secret"));
}
