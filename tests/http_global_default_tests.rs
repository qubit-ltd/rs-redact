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
/// Verifies HTTP defaults and explicitly loaded builders preserve a global
/// diagnostic budget snapshot.
#[test]
fn test_http_policy_defaults_preserve_global_diagnostic_budget() {
    let expected = InputOutputLimit::new(64, 64).expect("the diagnostic budget should be valid");
    let custom = RedactionPolicy::builder()
        .diagnostic_event(expected)
        .build()
        .expect("the custom global policy should be valid");
    RedactionPolicy::install_global(custom)
        .expect("this isolated test process installs the global configuration once");

    let default_policy = RedactionPolicy::default();
    let builder_policy = RedactionPolicy::default()
        .to_builder()
        .build()
        .expect("the HTTP redaction policy should be valid");

    assert_eq!(default_policy.limits().diagnostic_event(), expected);
    assert_eq!(builder_policy.limits().diagnostic_event(), expected);
    assert_eq!(default_policy, builder_policy);
}
