// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for serde redaction of map values.

#[cfg(feature = "serde")]
use std::{
    collections::BTreeMap,
    io::{
        self,
        Write,
    },
};

#[cfg(feature = "serde")]
use qubit_redact::{
    RedactedMap,
    RedactionPolicy,
};

#[cfg(feature = "serde")]
struct FailingWriter;

#[cfg(feature = "serde")]
impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("intentional test failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "serde")]
struct FailAfter {
    remaining: usize,
}

#[cfg(feature = "serde")]
impl Write for FailAfter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.remaining {
            return Err(io::Error::other("intentional test failure"));
        }
        self.remaining -= buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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

#[cfg(feature = "serde")]
#[test]
fn test_redact_map_serialize_propagates_destination_errors() {
    let map = BTreeMap::from([
        (String::from("label"), String::from("visible")),
        (String::from("password"), String::from("raw")),
    ]);
    let redacted = RedactedMap::new(&map, RedactionPolicy::default());

    assert!(serde_json::to_writer(FailingWriter, &redacted).is_err());
    let output_len = serde_json::to_vec(&redacted)
        .expect("the map should serialize")
        .len();
    for remaining in 0..output_len {
        assert!(
            serde_json::to_writer(FailAfter { remaining }, &redacted).is_err()
        );
    }
}
