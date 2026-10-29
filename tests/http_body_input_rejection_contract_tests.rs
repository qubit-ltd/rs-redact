// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

#![cfg(feature = "http")]

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

fn input_rejecting_redactor() -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(0).max_output_bytes(128);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should be valid");
    Redactor::new(policy)
}

fn assert_rejected(output: &qubit_redact::RedactionTextOutput, expected_text: &str) {
    assert_eq!(output.text().as_str(), expected_text);
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(output.summary().usage().inspected_input_bytes(), 0);
    assert_eq!(output.summary().usage().output_bytes(), expected_text.len());
}

#[test]
fn test_native_and_text_content_type_entries_record_input_rejection_without_body_text() {
    let native = input_rejecting_redactor().redact_http_body(BodyCapture::complete(b"x"), None);
    assert_rejected(&native, "");
    assert_eq!(native.text_or_marker("<omitted>"), "<omitted>");

    let textual = input_rejecting_redactor().redact_http_body_with_content_type_text(BodyCapture::complete(b"x"), None);
    assert_rejected(&textual, "");
    assert_eq!(textual.text_or_marker("<omitted>"), "<omitted>");
}

#[test]
fn test_composer_keeps_prefix_when_body_input_is_rejected() {
    let output = input_rejecting_redactor()
        .text_composer()
        .literal("body=")
        .http(|http| {
            http.body_with_content_type_text(BodyCapture::complete(b"x"), None);
        })
        .finish();

    assert_rejected(&output, "body=");
    assert_eq!(output.text_or_marker("<omitted>"), "<omitted>");
}

#[test]
fn test_batch_native_and_text_entries_resolve_rejection_to_marker() {
    let redactor = input_rejecting_redactor();
    let mut native_batch = redactor.diagnostic_batch();
    let native_handle = native_batch.redact_http_body(BodyCapture::complete(b"x"), None);
    let native = native_batch.finish_with_marker("<omitted>");
    assert_eq!(native.text(native_handle).as_str(), "<omitted>");

    let mut text_batch = redactor.diagnostic_batch();
    let text_handle = text_batch.redact_http_body_with_content_type_text(BodyCapture::complete(b"x"), None);
    let textual = text_batch.finish_with_marker("<omitted>");
    assert_eq!(textual.text(text_handle).as_str(), "<omitted>");
}
