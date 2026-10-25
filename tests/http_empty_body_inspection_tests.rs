// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "http")]

use http::HeaderValue;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

#[test]
fn test_empty_json_inspection_matches_text_and_header_rendering_admission() {
    let redactor = Redactor::standard();
    let capture = BodyCapture::complete(b"");
    let text_error = redactor
        .inspect_http_body_with_content_type_text(capture, Some("application/json; charset=utf-8"))
        .expect_err("empty JSON is invalid");
    let header = HeaderValue::from_static("application/json; charset=utf-8");
    let header_error = redactor
        .inspect_http_body(capture, Some(&header))
        .expect_err("header entry point must reject empty JSON too");
    let rendered = redactor.redact_http_body_with_content_type_text(capture, Some("application/json; charset=utf-8"));

    assert!(text_error.reasons().contains(RedactionReason::InvalidJson));
    assert_eq!(text_error.reasons(), header_error.reasons());
    assert_eq!(text_error.usage().output_bytes(), 0);
    assert!(rendered.summary().reasons().contains(RedactionReason::InvalidJson));
}

#[test]
fn test_empty_non_json_bodies_keep_their_existing_inspection_contract() {
    let redactor = Redactor::standard();
    let capture = BodyCapture::complete(b"");
    for content_type in [
        None,
        Some("application/x-ndjson"),
        Some("application/x-www-form-urlencoded"),
        Some("text/plain"),
    ] {
        let result = redactor.inspect_http_body_with_content_type_text(capture, content_type);
        assert!(
            result.is_ok(),
            "empty body with {content_type:?} should remain conclusive"
        );
        assert_eq!(result.expect("checked above").usage().output_bytes(), 0);
    }
}
