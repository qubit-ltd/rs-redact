// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for serde redaction of map values.

#[cfg(feature = "serde")]
use std::collections::BTreeMap;

#[cfg(feature = "serde")]
use qubit_redact::{
    RedactedMap,
    RedactionPolicy,
};

/// Verifies map serialization masks values classified from their keys.
#[cfg(feature = "serde")]
#[test]
fn test_redact_map_serialize_masks_sensitive_value() {
    let map = BTreeMap::from([(String::from("password"), String::from("raw"))]);
    let serialized = serde_json::to_string(&RedactedMap::new(
        &map,
        RedactionPolicy::default(),
    ))
    .expect("redacted map serialization should succeed");

    assert!(!serialized.contains("raw"));
}

/// Verifies serialization supports borrowed keys and optional text values.
#[cfg(feature = "serde")]
#[test]
fn test_redact_map_serialize_supports_borrowed_keys_and_optional_values() {
    let map = BTreeMap::from([
        ("label", Some(String::from("visible"))),
        ("password", Some(String::from("raw"))),
        ("secret", None),
    ]);

    let serialized = serde_json::to_value(RedactedMap::new(
        &map,
        RedactionPolicy::default(),
    ))
    .expect("redacted map serialization should succeed");

    assert_eq!(
        serialized,
        serde_json::json!({
            "label": "visible",
            "password": "<redacted>",
            "secret": null,
        }),
    );
}
