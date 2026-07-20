// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for the optional domain-object derive macro.

#![cfg(feature = "derive")]

use qubit_redact::Redact;

/// A record whose fields have no explicit redaction attributes.
#[derive(Redact)]
struct PlainRecord {
    /// Stable public identifier.
    id: u64,
    /// Display name kept visible by the minimal derive.
    name: String,
}

/// Verifies that the minimal derive preserves ordinary named fields.
#[test]
fn test_derive_keeps_unmarked_fields_visible_without_recursion() {
    let value = PlainRecord {
        id: 1,
        name: "Alice".to_owned(),
    };

    assert_eq!(
        format!("{:?}", value.redacted()),
        "PlainRecord { id: 1, name: \"Alice\" }",
    );
}
