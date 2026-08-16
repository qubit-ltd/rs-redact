// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable URI policy accessors.

use qubit_redact::RedactionPolicy;
use qubit_redact::formats::uri::UriFragmentPolicy;
use qubit_redact::formats::uri::UriPathPolicy;
/// Verifies the URI snapshot exposes its default path and fragment choices.
#[test]
fn test_uri_policy_exposes_default_behavior() {
    let policy = RedactionPolicy::default();

    assert_eq!(policy.uri().path_policy(), UriPathPolicy::Preserve);
    assert_eq!(policy.uri().fragment_policy(), UriFragmentPolicy::Redact);
}
