// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::http::BodyCapture;
use qubit_redact::http::HttpRedactor;

#[test]
fn output_exhaustion_skips_body_input() {
    let budget = InputOutputLimit::new(8, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("marker-sized output budget is valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("policy is valid");
    let redactor = HttpRedactor::new(policy);
    let mut session = redactor.session();
    let _ = session
        .http()
        .redact_url_str("https://user:password@example.com/path?token=secret");
    let input_before = session.remaining_input_bytes();
    let result = session.http().redact_body_with_content_type_text(
        BodyCapture::complete(br#"{"token":"must-not-be-read"}"#),
        Some("application/json"),
    );
    assert_eq!(result.completion(), RedactionCompletion::Exhausted);
    assert_eq!(result.log_safe_text().as_str(), "");
    assert_eq!(session.remaining_input_bytes(), input_before);
}

#[test]
fn input_rejection_with_body_marker_is_truncated() {
    let budget = InputOutputLimit::new(8, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("marker-sized output budget is valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("policy is valid");
    let redactor = HttpRedactor::new(policy);
    let mut session = redactor.session();

    let result = session.http().redact_body_with_content_type_text(
        BodyCapture::complete(br#"{"token":"secret"}"#),
        Some("application/json"),
    );

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(!result.log_safe_text().as_str().is_empty());
}

#[test]
fn complete_body_redaction_is_complete() {
    let budget = InputOutputLimit::new(256, 256).expect("budget is valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("policy is valid");
    let redactor = HttpRedactor::new(policy);
    let mut session = redactor.session();

    let result = session.http().redact_body_with_content_type_text(
        BodyCapture::complete(br#"{"token":"secret"}"#),
        Some("application/json"),
    );

    assert_eq!(result.completion(), RedactionCompletion::Complete);
    assert_eq!(result.log_safe_text().as_str(), r#"{"token":"****"}"#);
}

#[test]
fn output_smaller_than_truncation_marker_is_exhausted() {
    let budget = InputOutputLimit::new(256, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("marker-sized output budget is valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("policy is valid");
    let redactor = HttpRedactor::new(policy);
    let mut session = redactor.session();
    let first = session.http().redact_url_str("https://example.com/1234567");
    assert_eq!(first.as_str(), "https://example.com/1234567");
    assert!(session.remaining_output_bytes() < "<truncated>".len());

    let result = session.http().redact_body_with_content_type_text(
        BodyCapture::complete(b"body output cannot fit"),
        Some("text/plain"),
    );

    assert_eq!(result.completion(), RedactionCompletion::Exhausted);
    assert_eq!(result.log_safe_text().as_str(), "");
}
