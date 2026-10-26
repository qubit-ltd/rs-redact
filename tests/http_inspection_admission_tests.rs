// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "http")]

use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

fn redactor_with_input_limit(max_input_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(max_input_bytes);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    Redactor::new(policy)
}

#[test]
fn test_invalid_native_content_type_is_rejected_by_input_admission_first() {
    let redactor = redactor_with_input_limit(0);
    let invalid = HeaderValue::from_bytes(b"\xff").expect("header byte is allowed");
    let error = redactor
        .inspect_http_body(BodyCapture::complete(b""), Some(&invalid))
        .expect_err("zero input budget must reject the header bytes");

    assert!(error.reasons().contains(RedactionReason::InputLimitReached));
    assert!(!error.reasons().contains(RedactionReason::InvalidContentType));
    assert_eq!(error.usage().presented_input_bytes(), 1);
    assert_eq!(error.usage().inspected_input_bytes(), 0);
}

#[test]
fn test_invalid_native_content_type_is_reported_after_successful_admission() {
    let invalid = HeaderValue::from_bytes(b"\xff").expect("header byte is allowed");
    let error = redactor_with_input_limit(1)
        .inspect_http_body(BodyCapture::complete(b""), Some(&invalid))
        .expect_err("non-text content type is invalid");

    assert!(error.reasons().contains(RedactionReason::InvalidContentType));
    assert_eq!(error.usage().presented_input_bytes(), 1);
    assert_eq!(error.usage().inspected_input_bytes(), 1);
}

#[test]
fn test_native_and_text_content_type_share_atomic_input_boundaries() {
    let body = BodyCapture::complete(b"ok");
    let content_type = "text/plain";
    let header = HeaderValue::from_static(content_type);
    let total_bytes = body.captured_len() + content_type.len();

    for (limit, should_admit) in [(0, false), (total_bytes, true), (total_bytes - 1, false)] {
        let redactor = redactor_with_input_limit(limit);
        let native = redactor.inspect_http_body(body, Some(&header));
        let textual = redactor.inspect_http_body_with_content_type_text(body, Some(content_type));

        assert_eq!(native.is_ok(), should_admit, "native limit {limit}");
        assert_eq!(textual.is_ok(), should_admit, "text limit {limit}");
        let native_usage = native.as_ref().map_or_else(|error| error.usage(), |ok| ok.usage());
        let text_usage = textual.as_ref().map_or_else(|error| error.usage(), |ok| ok.usage());
        assert_eq!(native_usage.presented_input_bytes(), total_bytes);
        assert_eq!(text_usage.presented_input_bytes(), total_bytes);
        assert_eq!(
            native_usage.inspected_input_bytes(),
            if should_admit { total_bytes } else { 0 }
        );
        assert_eq!(
            text_usage.inspected_input_bytes(),
            if should_admit { total_bytes } else { 0 }
        );
        if !should_admit {
            assert!(
                native
                    .unwrap_err()
                    .reasons()
                    .contains(RedactionReason::InputLimitReached)
            );
            assert!(
                textual
                    .unwrap_err()
                    .reasons()
                    .contains(RedactionReason::InputLimitReached)
            );
        }
    }
}

#[test]
fn test_long_content_type_is_rejected_before_parsing_when_budget_is_small() {
    let content_type = format!("text/plain; charset={}", "a".repeat(128));
    let header = HeaderValue::from_str(&content_type).expect("ASCII metadata is a valid header");
    let redactor = redactor_with_input_limit(8);
    let capture = BodyCapture::complete(b"body");
    let native = redactor.inspect_http_body(capture, Some(&header));
    let textual = redactor.inspect_http_body_with_content_type_text(capture, Some(&content_type));

    for error in [native.unwrap_err(), textual.unwrap_err()] {
        assert!(error.reasons().contains(RedactionReason::InputLimitReached));
        assert!(!error.reasons().contains(RedactionReason::InvalidContentType));
        assert_eq!(error.usage().inspected_input_bytes(), 0);
        assert_eq!(error.usage().presented_input_bytes(), 4 + content_type.len());
    }
}

#[test]
fn test_64_kib_content_type_is_rejected_before_parsing_when_budget_is_small() {
    let prefix = "text/plain; charset=";
    let content_type = format!("{prefix}{}", "a".repeat(64 * 1024 - prefix.len()));
    assert_eq!(content_type.len(), 64 * 1024);
    let header = HeaderValue::from_str(&content_type).expect("64 KiB ASCII metadata is a valid header");
    let redactor = redactor_with_input_limit(8);
    let capture = BodyCapture::complete(b"body");
    let native = redactor.inspect_http_body(capture, Some(&header));
    let textual = redactor.inspect_http_body_with_content_type_text(capture, Some(&content_type));

    for error in [native.unwrap_err(), textual.unwrap_err()] {
        assert!(error.reasons().contains(RedactionReason::InputLimitReached));
        assert!(!error.reasons().contains(RedactionReason::InvalidContentType));
        assert_eq!(error.usage().inspected_input_bytes(), 0);
        assert_eq!(error.usage().presented_input_bytes(), 4 + 64 * 1024);
    }
}

#[test]
fn test_admitted_source_truncation_is_reported_after_metadata_admission() {
    let content_type = "text/plain";
    let header = HeaderValue::from_static(content_type);
    let capture = BodyCapture::truncated(b"prefix", 20).expect("source metadata");
    let captured_and_metadata_bytes = capture.captured_len() + content_type.len();
    let redactor = redactor_with_input_limit(captured_and_metadata_bytes);
    let native = redactor.inspect_http_body(capture, Some(&header)).unwrap_err();
    let textual = redactor
        .inspect_http_body_with_content_type_text(capture, Some(content_type))
        .unwrap_err();

    for error in [native, textual] {
        assert!(error.reasons().contains(RedactionReason::SourceTruncated));
        assert_eq!(error.usage().presented_input_bytes(), 20 + content_type.len());
        assert_eq!(error.usage().inspected_input_bytes(), captured_and_metadata_bytes);
    }
}

#[test]
fn test_empty_json_and_non_json_bodies_keep_inspection_contract_after_admission() {
    let redactor = Redactor::standard();
    let capture = BodyCapture::complete(b"");
    for (content_type, expected_reason) in [
        ("application/json", Some(RedactionReason::InvalidJson)),
        ("text/plain", None),
    ] {
        let header = HeaderValue::from_str(content_type).expect("valid metadata");
        let native = redactor.inspect_http_body(capture, Some(&header));
        let textual = redactor.inspect_http_body_with_content_type_text(capture, Some(content_type));
        assert_eq!(native.is_ok(), expected_reason.is_none());
        assert_eq!(textual.is_ok(), expected_reason.is_none());
        if let Some(reason) = expected_reason {
            assert!(native.unwrap_err().reasons().contains(reason));
            assert!(textual.unwrap_err().reasons().contains(reason));
        } else {
            assert_eq!(native.unwrap().usage().presented_input_bytes(), content_type.len());
            assert_eq!(textual.unwrap().usage().presented_input_bytes(), content_type.len());
        }
    }
}
