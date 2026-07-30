// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for public effects of unkeyed JSON value policy selection.

#[cfg(feature = "http")]
use http::HeaderValue;
#[cfg(feature = "http")]
use qubit_redact::http::{
    BodyCapture,
    BodyRedactionStatus,
    HttpRedactor,
};

/// Verifies the default policy redacts unkeyed JSON scalar values.
#[cfg(feature = "http")]
#[test]
fn test_json_unkeyed_value_policy_redacts_root_scalar_by_default() {
    let content_type = HeaderValue::from_static("application/json");
    let body = HttpRedactor::default().redact_body(
        BodyCapture::complete(br#""raw-root-value""#),
        Some(&content_type),
    );

    assert_eq!(body.status(), BodyRedactionStatus::Structured);
    assert!(!body.to_string().contains("raw-root-value"));
}
