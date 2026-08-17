// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Isolated global-configuration tests for HTTP redaction policy construction.

#![cfg(feature = "http")]

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
/// Verifies HTTP defaults and explicitly loaded builders preserve a global
/// diagnostic budget snapshot.
#[test]
fn test_http_policy_defaults_preserve_global_diagnostic_budget() {
    let expected = InputOutputLimit::builder()
        .max_input_bytes(64)
        .max_output_bytes(64)
        .build()
        .expect("the diagnostic budget should be valid");
    let custom = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(expected);
        builder
    })
    .build()
    .expect("the custom global policy should be valid");
    let previous = Redactor::set_default(Redactor::new(custom));

    let default_policy = Redactor::default().policy().clone();
    let builder_policy = Redactor::default()
        .policy()
        .clone()
        .to_builder()
        .build()
        .expect("the HTTP redaction policy should be valid");

    assert_eq!(default_policy.limits().diagnostic_event(), expected);
    assert_eq!(builder_policy.limits().diagnostic_event(), expected);
    assert_eq!(default_policy, builder_policy);
    let _ = Redactor::set_default(previous);
}
