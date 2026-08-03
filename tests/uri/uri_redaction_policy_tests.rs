// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable URI redaction policies.

use qubit_redact::{
    RedactionPolicy,
    UriFragmentPolicy,
    UriPathPolicy,
    UriRedactionPolicy,
};

/// Verifies URI policy defaults preserve paths and redact fragments.
#[test]
fn test_uri_policy_defaults_are_safe() {
    let policy = UriRedactionPolicy::default();

    assert_eq!(UriPathPolicy::Preserve, policy.path_policy());
    assert_eq!(UriFragmentPolicy::Redact, policy.fragment_policy());
}

/// Verifies URI policy snapshots expose and preserve their builder state.
#[test]
fn test_uri_policy_builder_round_trips_core_and_boundaries() {
    let core = RedactionPolicy::default();
    let policy = UriRedactionPolicy::builder_from(&core)
        .path_policy(UriPathPolicy::Redact)
        .fragment_policy(UriFragmentPolicy::Preserve)
        .build()
        .expect("URI policy should be valid");
    let copied = policy.to_builder().build().expect("copy should be valid");

    assert_eq!(copied.redaction_policy(), &core);
    assert_eq!(copied.path_policy(), UriPathPolicy::Redact);
    assert_eq!(copied.fragment_policy(), UriFragmentPolicy::Preserve);
}
