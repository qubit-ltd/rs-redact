// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for JSON body redaction.

use http::HeaderValue;
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::http::HttpRedactor;
/// Verifies JSON redaction does not expose a secret field value.
#[test]
fn test_json_masks_secret_field_value() {
    let rendered = HttpRedactor::default()
        .redact_body(
            BodyCapture::complete(br#"{"password":"raw"}"#),
            Some(&HeaderValue::from_static("application/json")),
        )
        .to_string();

    assert!(!rendered.contains("raw"));
}
