// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for field-name canonicalization.

use qubit_redact::canonicalize_field_name;

#[test]
fn test_canonicalize_field_name_normalizes_supported_separators() {
    for name in [
        "access_token",
        "access-token",
        "access.token",
        "access Token",
    ] {
        assert_eq!(canonicalize_field_name(name), "accesstoken");
    }
}
