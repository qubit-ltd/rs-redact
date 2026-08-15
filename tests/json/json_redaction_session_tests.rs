// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use serde_json::json;

#[test]
fn output_exhaustion_skips_json_input() {
    let budget = InputOutputLimit::new(8, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("marker-sized output budget is valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let _ = session.json().redact_text("{\"token\":\"secret\"}");
    let input_before = session.remaining_input_bytes();
    let result = session.json().redact_value(&json!({
        "token": "must-not-be-read",
    }));
    assert_eq!(result.as_str(), "");
    assert_eq!(session.remaining_input_bytes(), input_before);
}

#[test]
fn redact_value_counts_input_and_returns_compact_json() {
    let policy = RedactionPolicy::builder()
        .diagnostic_event(
            InputOutputLimit::new(256, 256).expect("valid budget"),
        )
        .build()
        .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let result = session.json().redact_value(&json!({"token": "secret"}));

    assert_eq!(result.as_str(), r#"{"token":"****"}"#);
    assert!(session.remaining_input_bytes() < 256);
}

#[test]
fn redact_text_renders_json_through_the_shared_session() {
    let policy = RedactionPolicy::builder()
        .diagnostic_event(
            InputOutputLimit::new(256, 256).expect("valid budget"),
        )
        .build()
        .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let result = session.json().redact_text(r#"{"token":"secret"}"#);

    assert_eq!(result.as_str(), r#"{"token":"****"}"#);
}
