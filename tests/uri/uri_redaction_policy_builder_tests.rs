// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI redaction policy construction.

use qubit_redact::{
    UriFragmentPolicy,
    UriPathPolicy,
    UriRedactionPolicy,
};

/// Verifies the builder applies independent path and fragment controls.
#[test]
fn test_uri_policy_builder_configures_boundaries() {
    let policy = UriRedactionPolicy::builder()
        .path_policy(UriPathPolicy::Redact)
        .fragment_policy(UriFragmentPolicy::Preserve)
        .build()
        .expect("URI policy should be valid");

    assert_eq!(UriPathPolicy::Redact, policy.path_policy());
    assert_eq!(UriFragmentPolicy::Preserve, policy.fragment_policy());
}
