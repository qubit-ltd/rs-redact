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
use qubit_redact::RedactionPolicy;
#[cfg(feature = "serde")]
use qubit_redact::domain::RedactMapSerialize;

/// Verifies map serialization masks values classified from their keys.
#[cfg(feature = "serde")]
#[test]
fn test_redact_map_serialize_masks_sensitive_value() {
    let map = BTreeMap::from([(String::from("password"), String::from("raw"))]);
    let mut serializer = serde_json::Serializer::new(Vec::new());
    map.serialize_redacted_map(&RedactionPolicy::default(), &mut serializer)
        .expect("redacted map serialization should succeed");
    let serialized = String::from_utf8(serializer.into_inner()).expect("JSON must be UTF-8");

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

    let mut serializer = serde_json::Serializer::new(Vec::new());
    map.serialize_redacted_map(&RedactionPolicy::default(), &mut serializer)
        .expect("redacted map serialization should succeed");
    let serialized: serde_json::Value =
        serde_json::from_slice(&serializer.into_inner()).expect("serialized map must be valid JSON");

    assert_eq!(
        serialized,
        serde_json::json!({
            "label": "visible",
            "password": "<redacted>",
            "secret": null,
        }),
    );
}
