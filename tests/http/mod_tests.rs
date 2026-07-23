// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public HTTP module boundary.

use http::HeaderValue;
use qubit_redact::http::{
    BodyCapture,
    HttpRedactor,
};

/// Verifies the module reexports compose into structured body redaction.
#[test]
fn test_http_module_reexports_compose() {
    let result = HttpRedactor::default().redact_body(
        BodyCapture::complete(br#"{"password":"raw-secret"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert!(!result.to_string().contains("raw-secret"));
}
