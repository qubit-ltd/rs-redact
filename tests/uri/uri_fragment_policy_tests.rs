// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI fragment handling policy.

use qubit_redact::uri::UriFragmentPolicy;
/// Verifies fragments default to fail-closed redaction.
#[test]
fn test_fragment_policy_defaults_to_redact() {
    assert_eq!(UriFragmentPolicy::Redact, UriFragmentPolicy::default());
}
