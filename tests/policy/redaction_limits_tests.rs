// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for policy redaction limit propagation.

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
/// Verifies immutable policies preserve the configured diagnostic limits.
#[test]
fn test_redaction_limits_preserve_policy_diagnostic_budget() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(128)
        .max_output_bytes(256)
        .build()
        .expect("the test budget is valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the policy should build with the configured budget");

    assert_eq!(policy.limits().diagnostic_event(), budget);
    assert_eq!(
        RedactionPolicy::builder_from(&policy)
            .build()
            .expect("the copied policy should build")
            .limits()
            .diagnostic_event(),
        budget,
    );
}
