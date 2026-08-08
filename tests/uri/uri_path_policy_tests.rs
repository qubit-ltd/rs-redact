// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI path handling policy.

use qubit_redact::UriPathPolicy;
/// Verifies paths remain visible unless explicitly configured otherwise.
#[test]
fn test_path_policy_defaults_to_preserve() {
    assert_eq!(UriPathPolicy::Preserve, UriPathPolicy::default());
}
