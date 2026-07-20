// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for [`Redactor`](qubit_redact::Redactor).

use std::collections::{
    BTreeMap,
    HashMap,
};

use qubit_redact::Redactor;

/// Verifies that default field rules redact known secrets without changing the
/// source map.
#[test]
fn test_default_redactor_redacts_known_map_values() {
    let source = HashMap::from([
        ("username".to_string(), "alice".to_string()),
        ("password".to_string(), "secret".to_string()),
        ("OPENAI_API_KEY".to_string(), "sk-123".to_string()),
    ]);

    let redacted = Redactor::default().redact_map(&source);

    assert_eq!(redacted["username"], "alice");
    assert_eq!(redacted["password"], "<redacted>");
    assert_eq!(redacted["OPENAI_API_KEY"], "****");
    assert_eq!(source["password"], "secret");
}

/// Verifies that in-place map redaction supports ordered maps.
#[test]
fn test_redact_map_in_place_supports_btree_map() {
    let mut source = BTreeMap::from([
        ("password".to_string(), "secret".to_string()),
        ("username".to_string(), "alice".to_string()),
    ]);

    Redactor::default().redact_map_in_place(&mut source);

    assert_eq!(source["password"], "<redacted>");
    assert_eq!(source["username"], "alice");
}

/// Verifies that non-sensitive scalar values retain their input borrowing.
#[test]
fn test_redact_keeps_non_sensitive_value_borrowed() {
    let input = String::from("alice");
    let redacted = Redactor::default().redact("username", &input);

    assert!(std::ptr::eq(redacted.as_str(), input.as_str()));
}
