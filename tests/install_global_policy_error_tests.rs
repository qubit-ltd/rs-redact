// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for global-policy installation errors.

use qubit_redact::RedactionPolicy;
/// Verifies a rejected global policy remains recoverable by the caller.
#[test]
fn test_install_global_policy_error_returns_rejected_policy() {
    let installed = ({
        let mut builder = RedactionPolicy::builder();
        builder.legacy_fields().disable_floor();
        builder
    })
    .build()
    .expect("the installed policy must be valid");
    RedactionPolicy::install_global(installed)
        .expect("this isolated test process installs the global policy once");

    let rejected = ({
        let mut builder = RedactionPolicy::default().to_builder();
        builder.legacy_fields().disable_floor();
        builder
    })
    .build()
    .expect("the rejected policy must be valid");
    let recovered = RedactionPolicy::install_global(rejected.clone())
        .expect_err("the second global policy installation must fail")
        .into_policy();

    assert_eq!(recovered, rejected);
}
