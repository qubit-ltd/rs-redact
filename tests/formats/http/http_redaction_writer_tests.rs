// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP body line preservation through public diagnostic output.

use http::HeaderValue;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

/// Verifies the admitted NDJSON model retains empty source lines.
#[test]
fn test_enabled_http_ndjson_preserves_empty_lines() {
    let output = Redactor::standard().redact_http_body(
        BodyCapture::complete(b"{\"name\":\"one\"}\n\n{\"name\":\"two\"}\n"),
        Some(&HeaderValue::from_static("application/x-ndjson")),
    );

    assert_eq!(output.text().as_str(), "{\"name\":\"one\"}\\n\\n{\"name\":\"two\"}\\n");
}

/// Verifies the public JSON HTTP adapter preserves numeric representations.
#[test]
fn test_enabled_http_json_text_preserves_native_numbers() {
    let output = Redactor::standard().redact_http_body(
        BodyCapture::complete(br#"{"amount":1.5,"values":[-0.0,1e2,-9223372036854775808,18446744073709551615]}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert_eq!(
        output.summary().completion(),
        qubit_redact::RedactionCompletion::Complete
    );
    assert!(output.text().as_str().contains("1.5"));
    assert!(output.text().as_str().contains("-9223372036854775808"));
    assert!(output.text().as_str().contains("18446744073709551615"));
}
