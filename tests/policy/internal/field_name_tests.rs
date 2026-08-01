// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for field-name normalization used by policy matching.

use qubit_redact::{RedactionPolicy, Sensitivity};

/// Verifies that every supported separator produces the same canonical name.
#[test]
fn test_canonicalize_field_name_normalizes_supported_separators() {
    let policy = RedactionPolicy::empty_builder()
        .raise("access_token", Sensitivity::High)
        .build()
        .expect("the normalized field rule should be valid");
    for name in [
        "access_token",
        "access-token",
        "access.token",
        "access Token",
        " access[token] ",
    ] {
        assert_eq!(policy.sensitivity_for(name), Some(Sensitivity::High));
    }
}
