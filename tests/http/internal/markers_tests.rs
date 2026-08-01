// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for bounded-body truncation markers.

use http::HeaderValue;
use qubit_redact::http::{
    BodyBudget,
    BodyCapture,
    DiagnosticBudget,
    HttpRedactionPolicy,
    HttpRedactor,
    TextBodyPolicy,
};

/// Verifies output truncation appends the complete marker.
#[test]
fn test_markers_append_truncation_marker() {
    let budget = BodyBudget::new(64, BodyBudget::MIN_OUTPUT_BYTES)
        .expect("the minimum output budget should be valid");
    let policy = HttpRedactionPolicy::builder()
        .body_budget(budget)
        .text_body_policy(TextBodyPolicy::PassThrough)
        .build()
        .expect("the HTTP policy should be valid");
    let rendered = HttpRedactor::new(policy)
        .redact_body(
            BodyCapture::complete(b"payload larger than marker"),
            Some(&HeaderValue::from_static("text/plain")),
        )
        .to_string();

    assert_eq!(rendered, "<truncated>");
}
/// Verifies the minimum diagnostic budget can contain its fixed limit marker.
#[test]
fn test_diagnostic_limit_marker_matches_minimum_budget() {
    let budget = DiagnosticBudget::new(1, DiagnosticBudget::MIN_OUTPUT_BYTES)
        .expect("the minimum diagnostic output budget should be valid");
    let policy = HttpRedactionPolicy::builder()
        .diagnostic_budget(budget)
        .build()
        .expect("the HTTP policy should be valid");
    let rendered = HttpRedactor::new(policy)
        .redact_url_str("https://example.test/")
        .to_string();

    assert_eq!(rendered, "<redacted: diagnostic limit exceeded>");
    assert_eq!(rendered.len(), DiagnosticBudget::MIN_OUTPUT_BYTES);
}
