// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Source-pair marker for the private URI policy state module.

/// Keeps the private policy state covered through its public facade.
#[test]
fn test_uri_policy_inner_is_exercised_by_public_policy() {
    let _ = qubit_redact::UriRedactionPolicy::default();
}
