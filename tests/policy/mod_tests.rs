// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public policy module boundary.

use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
/// Verifies builder and immutable policy reexports compose.
#[test]
fn test_policy_module_reexports_compose() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("token", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the module-level policy rule is valid");

    assert_eq!(policy.sensitivity_for("token"), Some(Sensitivity::Secret));
}
