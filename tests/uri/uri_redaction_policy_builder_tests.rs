// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI redaction policy construction.

use qubit_redact::{
    RedactionPolicy,
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

/// Verifies every builder construction path retains the supplied core policy.
#[test]
fn test_uri_policy_builder_accepts_explicit_core_and_uri_snapshots() {
    let core = RedactionPolicy::default();
    let explicit = UriRedactionPolicy::builder()
        .redaction_policy(core.clone())
        .build()
        .expect("explicit core policy should be valid");
    let from_uri = UriRedactionPolicy::builder()
        .redaction_policy(explicit.redaction_policy().clone())
        .path_policy(explicit.path_policy())
        .fragment_policy(explicit.fragment_policy())
        .build()
        .expect("URI snapshot should be valid");
    let default_builder = qubit_redact::UriRedactionPolicyBuilder::default();

    assert_eq!(explicit.redaction_policy(), &core);
    assert_eq!(from_uri, explicit);
    assert_eq!(
        default_builder.build().expect("default builder is valid"),
        UriRedactionPolicy::default(),
    );
}
