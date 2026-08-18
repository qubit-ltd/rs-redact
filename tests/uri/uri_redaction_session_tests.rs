// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared-session URI regression tests.

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::formats::uri::UriRedactionReason;
use qubit_redact::formats::uri::UriRedactionStatus;
use qubit_redact::formats::uri::UriRedactor;

/// Verifies output exhaustion short-circuits later URI input admission.
#[test]
fn test_uri_session_does_not_charge_input_after_output_exhaustion() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(8)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the marker-sized diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the URI policy should build");
    let redactor = UriRedactor::new(policy);
    let mut session = redactor.session();
    let _ = session
        .uri_with_mut(|uri| uri.redact_uri_str("scheme://user:secret@example.test/private?token=secret#fragment"));
    let input_before = session.remaining_input_bytes();
    let second = session.uri_with_mut(|uri| uri.redact_uri_str("scheme://unread-secret"));
    assert_eq!(second.completion(), RedactionCompletion::Truncated);
    assert_eq!(second.status(), UriRedactionStatus::Invalid);
    assert!(second.has_reason(UriRedactionReason::InputLimitExceeded));
    assert_eq!(second.log_safe_text().as_str(), "<invalid URI>");
    assert_eq!(session.remaining_input_bytes(), input_before);
    let third = session.uri_with_mut(|uri| uri.redact_uri_str("https://must-not-be-read"));
    assert_eq!(third.completion(), RedactionCompletion::Exhausted);
    assert_eq!(third.status(), UriRedactionStatus::Invalid);
    assert!(third.has_reason(UriRedactionReason::OutputTruncated));
    assert_eq!(third.log_safe_text().as_str(), "");
    assert_eq!(session.remaining_input_bytes(), input_before);
}

/// Verifies a complete safe rewrite reports explicit complete output.
#[test]
fn test_uri_session_reports_complete_safe_rewrite() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(256)
        .max_output_bytes(256)
        .build()
        .expect("the diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the URI policy should build");
    let redactor = UriRedactor::new(policy);
    let mut session = redactor.session();

    let result = session.uri_with_mut(|uri| uri.redact_uri_str("https://example.test/?token=secret"));

    assert_eq!(result.completion(), RedactionCompletion::Complete);
    assert!(!result.log_safe_text().as_str().contains("secret"));
}

/// Verifies a non-empty output substitute reports truncation.
#[test]
fn test_uri_session_reports_non_empty_output_omission_as_truncated() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(256)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the URI policy should build");
    let redactor = UriRedactor::new(policy);
    let mut session = redactor.session();

    let result = session
        .uri_with_mut(|uri| uri.redact_uri_str(&format!("https://example.test/{}?token=secret", "a".repeat(128),)));

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(result.has_reason(UriRedactionReason::OutputTruncated));
    assert!(!result.log_safe_text().as_str().is_empty());
}
