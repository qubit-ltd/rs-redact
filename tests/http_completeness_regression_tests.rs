// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP output and source completeness regression tests.

#![cfg(feature = "http")]

use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::http::BodyCapture;

fn bounded_policy(field: &str, mask: &str, max_output_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise(field, Sensitivity::Secret);
            fields.mask(Sensitivity::Secret, MaskPolicy::fixed(mask));
        })
        .expect("field policy")
        .limits(|limits| {
            limits.max_output_bytes(max_output_bytes);
        })
        .expect("output limit")
        .build()
        .expect("policy");
    Redactor::new(policy)
}

fn assert_incomplete_redaction(output: &qubit_redact::RedactionTextOutput, secret: &str) {
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(output.complete_text().is_err());
    assert!(!output.text().as_str().contains(secret));
}

fn userinfo_redactor(high_mask: &str, secret_mask: &str, max_output_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .fields(|fields| {
            fields.raise("username", Sensitivity::High);
            fields.mask(Sensitivity::High, MaskPolicy::fixed(high_mask));
            fields.mask(Sensitivity::Secret, MaskPolicy::fixed(secret_mask));
        })
        .expect("field policy")
        .limits(|limits| {
            limits.max_output_bytes(max_output_bytes);
        })
        .expect("output limit")
        .build()
        .expect("policy");
    Redactor::new(policy)
}

#[test]
fn test_url_username_unicode_mask_truncation_is_reported_and_uses_batch_marker() {
    let redactor = userinfo_redactor("😀", "😀", 11);
    let url = "https://raw@a/";

    let direct = redactor.redact_http_url(url);
    assert_incomplete_redaction(&direct, "raw");
    assert!(direct.text().as_str().len() <= 11);
    assert!(direct.text().as_str().is_char_boundary(direct.text().as_str().len()));

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_url(url);
    let diagnostics = batch.finish_with_marker("<incomplete>");
    assert_eq!(diagnostics.text(handle).as_str(), "<incomplete>");
    assert!(
        diagnostics
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
}

#[test]
fn test_url_password_unicode_mask_truncation_and_complete_ascii_controls() {
    let truncated = userinfo_redactor("😀", "😀", 12);
    let direct = truncated.redact_http_url("https://:raw@a/");
    assert_incomplete_redaction(&direct, "raw");
    assert!(direct.text().as_str().len() <= 12);

    let sufficient = userinfo_redactor("😀", "😀", 64);
    let complete = sufficient.redact_http_url("https://raw:secret@a/");
    assert_eq!(complete.summary().completion(), RedactionCompletion::Complete);
    assert!(
        !complete
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
    assert!(!complete.text().as_str().contains("raw"));
    assert!(!complete.text().as_str().contains("secret"));

    let ascii = userinfo_redactor("U", "P", 64).redact_http_url("https://raw:secret@a/");
    assert_eq!(ascii.summary().completion(), RedactionCompletion::Complete);
    assert!(!ascii.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(ascii.text().as_str(), "https://U:P@a/");
}

#[test]
fn test_query_mask_truncation_is_reported_for_one_shot_and_batch() {
    let redactor = bounded_policy("x", "界", 24);
    let url = "https://example.test/?x=raw";

    let direct = redactor.redact_http_url(url);
    assert_incomplete_redaction(&direct, "raw");

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_url(url);
    let diagnostics = batch.finish_with_marker("<incomplete>");
    assert_eq!(diagnostics.text(handle).as_str(), "<incomplete>");
    assert_ne!(diagnostics.summary().completion(), RedactionCompletion::Complete);
    assert!(
        diagnostics
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
}

#[test]
fn test_form_mask_truncation_is_reported_for_one_shot_and_batch() {
    let redactor = bounded_policy("a", "😀", 2);
    let capture = || BodyCapture::complete(b"a=secret");

    let direct = redactor.redact_http_body_with_content_type_text(capture(), Some("application/x-www-form-urlencoded"));
    assert_incomplete_redaction(&direct, "secret");

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_body_with_content_type_text(capture(), Some("application/x-www-form-urlencoded"));
    let diagnostics = batch.finish_with_marker("<incomplete>");
    assert_eq!(diagnostics.text(handle).as_str(), "<incomplete>");
    assert_ne!(diagnostics.summary().completion(), RedactionCompletion::Complete);
    assert!(
        diagnostics
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
}

#[test]
fn test_disabled_body_preserves_source_and_output_truncation_facts() {
    let sufficient = Redactor::new(RedactionPolicy::disabled());
    let capture = || BodyCapture::truncated(b"prefix", 20).expect("source metadata");
    let source_truncated = sufficient.redact_http_body_with_content_type_text(capture(), Some("text/plain"));
    assert_ne!(source_truncated.summary().completion(), RedactionCompletion::Complete);
    assert!(
        source_truncated
            .summary()
            .reasons()
            .contains(RedactionReason::SourceTruncated)
    );
    assert!(source_truncated.summary().is_redaction_disabled());
    assert_eq!(source_truncated.summary().usage().inspected_input_bytes(), 16);

    let tight_policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_output_bytes(3);
        })
        .expect("output limit")
        .build()
        .expect("policy");
    let both = Redactor::new(tight_policy).redact_http_body_with_content_type_text(capture(), Some("text/plain"));
    assert_ne!(both.summary().completion(), RedactionCompletion::Complete);
    assert!(both.summary().reasons().contains(RedactionReason::SourceTruncated));
    assert!(both.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(both.summary().is_redaction_disabled());
    assert_eq!(both.summary().usage().inspected_input_bytes(), 16);

    let complete =
        sufficient.redact_http_body_with_content_type_text(BodyCapture::complete(b"prefix"), Some("text/plain"));
    assert_eq!(complete.summary().completion(), RedactionCompletion::Complete);
    assert!(complete.summary().is_redaction_disabled());
    assert_eq!(complete.text().as_str(), "prefix");
}
