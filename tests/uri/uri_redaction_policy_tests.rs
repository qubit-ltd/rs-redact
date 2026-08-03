// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable URI redaction policies.

use qubit_redact::{
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
