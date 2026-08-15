// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public regression coverage for diagnostic fragment admission.

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// Verifies rejected input keeps emitting charged fallbacks until the output
/// budget can no longer contain one.
#[test]
fn test_admission_allows_fallbacks_until_output_cannot_fit_one() {
    let limit = InputOutputLimit::new(1, InputOutputLimit::MIN_OUTPUT_BYTES)
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

    let fallback = "<redacted>";
    let fallback_capacity = limit.max_output_bytes() / fallback.len();
    for _ in 0..fallback_capacity {
        assert_eq!(
            session.redact_at(Sensitivity::Secret, "too-large").as_str(),
            fallback,
        );
    }
    let remaining_input = session.remaining_input_bytes();
    assert_eq!(session.redact_at(Sensitivity::Secret, "x").as_str(), "",);
    assert_eq!(session.remaining_input_bytes(), remaining_input);
    assert_eq!(session.remaining_output_bytes(), 0,);
}
