// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "http")]

use http::HeaderValue;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionReasons;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

fn redactor_with_limits(max_input_bytes: usize, max_nodes: usize, max_output_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_input_bytes(max_input_bytes)
                .max_nodes(max_nodes)
                .max_output_bytes(max_output_bytes);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    Redactor::new(policy)
}

fn has_invalid_content_type(reasons: RedactionReasons) -> bool {
    reasons.contains(RedactionReason::InvalidContentType)
}

#[test]
fn test_empty_invalid_content_type_is_reported_by_all_rendering_entry_points() {
    let redactor = Redactor::standard();
    let capture = BodyCapture::complete(b"");
    let invalid = "not-a-content-type";
    let invalid_header = HeaderValue::from_static(invalid);

    for rendered in [
        redactor.redact_http_body(capture, Some(&invalid_header)),
        redactor.redact_http_body_with_content_type_text(capture, Some(invalid)),
        redactor
            .text_composer()
            .http(|http| {
                http.body(capture, Some(&invalid_header));
            })
            .finish(),
        redactor
            .text_composer()
            .http(|http| {
                http.body_with_content_type_text(capture, Some(invalid));
            })
            .finish(),
    ] {
        assert!(has_invalid_content_type(rendered.summary().reasons()));
        assert_eq!(rendered.summary().completion(), RedactionCompletion::Complete);
    }

    let mut batch = redactor.diagnostic_batch();
    let native = batch.redact_http_body(capture, Some(&invalid_header));
    let textual = batch.redact_http_body_with_content_type_text(capture, Some(invalid));
    let report = batch.finish();
    assert!(!report.text(native).as_str().is_empty());
    assert!(!report.text(textual).as_str().is_empty());
    assert!(has_invalid_content_type(report.summary().reasons()));

    let non_text_header = HeaderValue::from_bytes(b"\xff").expect("raw header byte is permitted");
    let rendered = redactor.redact_http_body(capture, Some(&non_text_header));
    assert!(
        rendered
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidContentType)
    );
}

#[test]
fn test_nonempty_invalid_content_type_and_valid_or_missing_metadata_are_distinguished() {
    let redactor = Redactor::standard();
    let invalid_header = HeaderValue::from_static("not-a-content-type");
    let invalid = redactor.redact_http_body(BodyCapture::complete(b"body"), Some(&invalid_header));
    let invalid_text =
        redactor.redact_http_body_with_content_type_text(BodyCapture::complete(b"body"), Some("not-a-content-type"));
    for rendered in [invalid, invalid_text] {
        assert!(
            rendered
                .summary()
                .reasons()
                .contains(RedactionReason::InvalidContentType)
        );
    }

    let valid = redactor.redact_http_body_with_content_type_text(BodyCapture::complete(b""), Some("text/plain"));
    let missing = redactor.redact_http_body_with_content_type_text(BodyCapture::complete(b""), None);
    let unsupported = redactor.redact_http_body_with_content_type_text(BodyCapture::complete(b""), Some("image/png"));
    for rendered in [valid, missing] {
        assert!(
            !rendered
                .summary()
                .reasons()
                .contains(RedactionReason::InvalidContentType)
        );
        assert_eq!(rendered.summary().completion(), RedactionCompletion::Complete);
    }
    assert!(
        !unsupported
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidContentType)
    );
}

#[test]
fn test_invalid_native_and_text_content_type_inspection_agree_for_empty_body() {
    let redactor = Redactor::standard();
    let capture = BodyCapture::complete(b"");
    let invalid = "not-a-content-type";
    let header = HeaderValue::from_static(invalid);
    let native = redactor.inspect_http_body(capture, Some(&header)).unwrap_err();
    let textual = redactor
        .inspect_http_body_with_content_type_text(capture, Some(invalid))
        .unwrap_err();
    assert!(native.reasons().contains(RedactionReason::InvalidContentType));
    assert_eq!(native.reasons(), textual.reasons());
}

#[test]
fn test_invalid_content_type_diagnostic_respects_admission_and_publication_limits() {
    let invalid = "not-a-content-type";
    let header = HeaderValue::from_static(invalid);
    let capture = BodyCapture::complete(b"");
    let bytes = invalid.len();

    let rejected = redactor_with_limits(bytes - 1, 100_000, 1_000_000)
        .redact_http_body_with_content_type_text(capture, Some(invalid));
    assert!(
        rejected
            .summary()
            .reasons()
            .contains(RedactionReason::InputLimitReached)
    );
    assert!(
        !rejected
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidContentType)
    );

    let exact = redactor_with_limits(bytes, 100_000, 1_000_000).redact_http_body(capture, Some(&header));
    assert!(exact.summary().reasons().contains(RedactionReason::InvalidContentType));

    let no_nodes =
        redactor_with_limits(bytes, 0, 1_000_000).redact_http_body_with_content_type_text(capture, Some(invalid));
    assert!(
        no_nodes
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(
        !no_nodes
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidContentType)
    );

    let tiny_output =
        redactor_with_limits(bytes, 100_000, 1).redact_http_body_with_content_type_text(capture, Some(invalid));
    assert!(
        tiny_output
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
    assert!(
        tiny_output
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidContentType)
    );
}

#[test]
fn test_invalid_content_type_truncation_and_disabled_policy_keep_existing_semantics() {
    let invalid = "not-a-content-type";
    let truncated = BodyCapture::truncated(b"", 1).expect("truncated empty capture is valid");
    let rendered = Redactor::standard().redact_http_body_with_content_type_text(truncated, Some(invalid));
    assert!(rendered.summary().reasons().contains(RedactionReason::SourceTruncated));
    assert!(
        rendered
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidContentType)
    );

    let disabled = Redactor::new(RedactionPolicy::disabled())
        .redact_http_body_with_content_type_text(BodyCapture::complete(b""), Some(invalid));
    assert!(
        !disabled
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidContentType)
    );
    assert_eq!(disabled.summary().completion(), RedactionCompletion::Complete);
}
