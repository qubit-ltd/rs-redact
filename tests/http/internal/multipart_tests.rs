// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for multipart body redaction.

use http::HeaderValue;
use qubit_redact::http::{
    BodyCapture,
    BodyRedactionStatus,
    HttpRedactor,
};

/// Verifies multipart file contents are not included in diagnostics.
#[test]
fn test_multipart_hides_file_content() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"secret.txt\"\r\n\r\nfile-secret\r\n--boundary--\r\n";
    let result = HttpRedactor::default().redact_body(
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static(
            "multipart/form-data; boundary=boundary",
        )),
    );

    assert_eq!(result.status(), BodyRedactionStatus::Structured);
    assert!(!result.to_string().contains("file-secret"));
}
