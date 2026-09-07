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

    assert_eq!(output.text().as_str(), "{\"name\":\"one\"}\\n\\n{\"name\":\"two\"}\\n",);
}
