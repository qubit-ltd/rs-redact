// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Additional completion-state tests for diagnostic writes.

use qubit_redact::DiagnosticLogBuilder;
use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionCompletion;

/// Verifies a fragment that fits reports completion.
#[test]
fn test_redaction_completion_reports_complete_fragment() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(128)
        .max_output_bytes(64)
        .build()
        .expect("the test budget is valid");
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder.push_fmt(format_args!("short message")),
        Ok(RedactionCompletion::Complete),
    );
}

/// Verifies a fragment beyond the output budget reports truncation.
#[test]
fn test_redaction_completion_reports_truncated_fragment() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(128)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the test budget is valid");
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder.push_fmt(format_args!(
            "payload that cannot fit and is definitely longer than the marker"
        )),
        Ok(RedactionCompletion::Truncated),
    );
    assert!(builder.is_truncated());
}
