// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internal policy composition through the public builder.

use qubit_redact::FieldNameMatching;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
/// Verifies canonical storage and candidate matching compose consistently.
#[test]
fn test_policy_internal_components_share_canonical_state() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        let _ = builder
            .edit_fields()
            .matching(FieldNameMatching::ExactOrTokenSuffix);
        builder
            .edit_fields()
            .raise("access-token", Sensitivity::High)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the canonicalized rule is valid");

    assert_eq!(
        policy.sensitivity_for("serviceAccessToken"),
        Some(Sensitivity::High),
    );
}
