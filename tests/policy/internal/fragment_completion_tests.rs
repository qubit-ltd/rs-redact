// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public regression coverage for diagnostic fragment completion.

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

/// Verifies session truncation commits one fallback and closes later output.
#[test]
fn test_session_truncated_completion_closes_output() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(128)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the marker-sized test limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let long_value = "visible output ".repeat(6);

    assert_eq!(
        session.redact_field("message", &long_value).as_str(),
        "<redacted>",
    );
    let remaining_input = session.remaining_input_bytes();
    assert_eq!(session.redact_field("message", "next").as_str(), "");
    assert_eq!(session.remaining_input_bytes(), remaining_input);
}
