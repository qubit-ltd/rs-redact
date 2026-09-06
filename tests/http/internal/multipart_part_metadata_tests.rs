// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for multipart part metadata redaction.

use http::HeaderValue;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

use crate::http::support::redaction::redact_body;
/// Verifies multipart filenames are removed from rendered diagnostics.
#[test]
fn test_multipart_part_metadata_hides_filename() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"secret.txt\"\r\n\r\ncontent\r\n--boundary--\r\n";
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary")),
    );

    assert!(!rendered.contains("secret.txt"));
}
