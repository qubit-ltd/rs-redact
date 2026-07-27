// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Isolated global-default tests for HTTP redaction policy construction.

#![cfg(feature = "http")]

use qubit_redact::{DiagnosticBudget, RedactionPolicy, http::HttpRedactionPolicy};

/// Verifies HTTP default and builder policies preserve a global diagnostic
/// budget snapshot.
#[test]
fn test_http_policy_defaults_preserve_global_diagnostic_budget() {
    let expected = DiagnosticBudget::new(64, 64).expect("the diagnostic budget should be valid");
    let custom = RedactionPolicy::builder()
        .diagnostic_budget(expected)
        .build()
        .expect("the custom global policy should be valid");
    RedactionPolicy::set_global_default(custom)
        .expect("this isolated test process installs the global default once");

    let default_policy = HttpRedactionPolicy::default();
    let builder_policy = HttpRedactionPolicy::builder()
        .build()
        .expect("the HTTP redaction policy should be valid");

    assert_eq!(default_policy.diagnostic_budget(), expected);
    assert_eq!(builder_policy.diagnostic_budget(), expected);
    assert_eq!(default_policy, builder_policy);
}
