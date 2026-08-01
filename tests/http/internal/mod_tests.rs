// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internal HTTP parser dispatch through the public redactor.

use http::HeaderValue;
use qubit_redact::http::{
    BodyCapture,
    BodyRedactionStatus,
    HttpRedactor,
};

/// Verifies format dispatch selects a structured parser for form bodies.
#[test]
fn test_http_internal_dispatch_selects_structured_parser() {
    let result = HttpRedactor::default().redact_body(
        BodyCapture::complete(b"password=raw-secret&mode=visible"),
        Some(&HeaderValue::from_static(
            "application/x-www-form-urlencoded",
        )),
    );

    assert_eq!(result.status(), BodyRedactionStatus::Structured);
    assert!(!result.to_string().contains("raw-secret"));
}
