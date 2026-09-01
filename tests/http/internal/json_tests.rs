// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for JSON body redaction.

use http::HeaderValue;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

use crate::http::support::redaction::redact_body;
/// Verifies JSON redaction does not expose a secret field value.
#[test]
fn test_json_masks_secret_field_value() {
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(br#"{"password":"raw"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert!(!rendered.contains("raw"));
}

/// Verifies NDJSON bodies redact every record through the HTTP parser path.
#[test]
fn test_ndjson_masks_secrets_without_exposing_later_records() {
    let content_type = HeaderValue::from_static("application/x-ndjson");
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(b"{\"password\":\"first-secret\"}\n{\"token\":\"second-secret\"}\n"),
        Some(&content_type),
    );

    assert!(!rendered.contains("first-secret"));
    assert!(!rendered.contains("second-secret"));
    assert!(rendered.contains("password"));
    assert!(rendered.contains("token"));
}

/// Verifies malformed NDJSON is replaced by a safe diagnostic rather than
/// exposing the source line that failed parsing.
#[test]
fn test_malformed_ndjson_does_not_expose_source_text() {
    let content_type = HeaderValue::from_static("application/ndjson");
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(b"{\"password\":\"safe\"}\n{\"token\":\"raw-secret\""),
        Some(&content_type),
    );

    assert!(!rendered.contains("raw-secret"));
}

/// Verifies NDJSON applies the crate's 64-bit integer contract before
/// materializing a serde_json value.
#[test]
fn test_ndjson_rejects_integer_above_u64_without_exposing_source_text() {
    let content_type = HeaderValue::from_static("application/x-ndjson");
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(
            b"{\"password\":\"safe\"}\n{\"id\":18446744073709551616,\"token\":\"raw-secret\"}\n",
        ),
        Some(&content_type),
    );

    assert!(!rendered.contains("raw-secret"));
}
