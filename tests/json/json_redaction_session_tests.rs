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
use qubit_redact::Redactor;
use qubit_redact::UnkeyedJsonValuePolicy;
use serde_json::json;

#[test]
fn output_exhaustion_skips_json_input() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(8)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("marker-sized output budget is valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let _ = session.json_with_mut(|json| json.redact_text("{\"token\":\"secret\"}"));
    let input_before = session.remaining_input_bytes();
    let result = session.json_with_mut(|json| {
        json.redact_value(&json!({
            "token": "must-not-be-read",
        }))
    });
    assert_eq!(result.completion(), RedactionCompletion::Exhausted);
    assert_eq!(result.log_safe_text().as_str(), "");
    assert_eq!(session.remaining_input_bytes(), input_before);
}

#[test]
fn input_rejection_with_safe_fallback_is_truncated() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(8)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("marker-sized output budget is valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let result = session.json_with_mut(|json| json.redact_text(r#"{"token":"secret"}"#));

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(!result.log_safe_text().as_str().is_empty());
}

#[test]
fn redact_value_counts_input_and_returns_compact_json() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(
            InputOutputLimit::builder()
                .max_input_bytes(256)
                .max_output_bytes(256)
                .build()
                .expect("valid budget"),
        );
        builder
    })
    .build()
    .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let result = session.json_with_mut(|json| json.redact_value(&json!({"token": "secret"})));

    assert_eq!(result.completion(), RedactionCompletion::Complete);
    assert_eq!(result.log_safe_text().as_str(), r#"{"token":"****"}"#);
    assert!(session.remaining_input_bytes() < 256);
}

#[test]
fn redact_text_renders_json_through_the_shared_session() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(
            InputOutputLimit::builder()
                .max_input_bytes(256)
                .max_output_bytes(256)
                .build()
                .expect("valid budget"),
        );
        builder
    })
    .build()
    .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let result = session.json_with_mut(|json| json.redact_text(r#"{"token":"secret"}"#));

    assert_eq!(result.completion(), RedactionCompletion::Complete);
    assert_eq!(result.log_safe_text().as_str(), r#"{"token":"****"}"#);
}

#[test]
fn output_smaller_than_truncation_marker_is_exhausted() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(256)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("marker-sized output budget is valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let first = session.json_with_mut(|json| json.redact_text(r#"{"message":"abcdefghijklm"}"#));
    assert_eq!(first.completion(), RedactionCompletion::Complete);
    assert!(session.remaining_output_bytes() < "<truncated>".len());

    let result = session.json_with_mut(|json| json.redact_text(r#"{"message":"this output cannot fit"}"#));

    assert_eq!(result.completion(), RedactionCompletion::Exhausted);
    assert_eq!(result.log_safe_text().as_str(), "");
}

#[test]
fn generated_mask_budget_exhaustion_is_truncated() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(256)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("marker-sized output budget is valid");
    let mut builder = RedactionPolicy::builder();
    builder.limits().diagnostic_event(budget);
    let policy = builder
        .unkeyed_json_value_policy(UnkeyedJsonValuePolicy::Redact)
        .build()
        .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let values = json!([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,]);

    let result = session.json_with_mut(|json| json.redact_value(&values));

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(!result.log_safe_text().as_str().is_empty());
}
