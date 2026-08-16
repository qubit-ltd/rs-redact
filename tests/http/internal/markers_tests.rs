// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for bounded-body truncation markers.

use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::formats::http::BodyBudget;
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::http::HttpRedactor;
use qubit_redact::formats::http::InputOutputLimit;
use qubit_redact::formats::http::TextBodyPolicy;
/// Verifies output truncation appends the complete marker.
#[test]
fn test_markers_append_truncation_marker() {
    let budget = BodyBudget::builder()
        .max_input_bytes(64)
        .max_output_bytes(BodyBudget::MIN_OUTPUT_BYTES)
        .build()
        .expect("the minimum output budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().http_body(budget);
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
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
    let budget = InputOutputLimit::builder()
        .max_input_bytes(1)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the minimum diagnostic output budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the HTTP policy should be valid");
    let rendered = HttpRedactor::new(policy)
        .redact_url_str("https://example.test/")
        .to_string();

    assert_eq!(rendered, "<redacted: diagnostic limit exceeded>");
    assert_eq!(rendered.len(), InputOutputLimit::MIN_OUTPUT_BYTES);
}
