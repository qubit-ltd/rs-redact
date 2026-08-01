// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internally tagged redacted newtype serialization.

#![cfg(feature = "serde")]

use std::{
    collections::BTreeMap,
    io::{
        self,
        Write,
    },
};

use qubit_redact::{
    __private::serialize_internally_tagged,
    Redact,
};
use qubit_redact_derive::Redact;
use serde::{
    Serialize,
    Serializer,
    ser::SerializeMap,
};
use serde_json::{
    Error,
    Value,
    value::Serializer as ValueSerializer,
};

/// Map-like newtype content accepted by internal tagging.
#[derive(Redact, Serialize)]
#[redact(serde)]
struct Payload {
    /// Sensitive payload field.
    #[redact(level = "secret")]
    secret: String,
}

/// Internally tagged newtype variant using the hidden serializer adapter.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum Event {
    /// Newtype payload.
    Payload(#[redact(nested)] Payload),
}

/// Unit-struct content used to exercise the corresponding serializer entry.
#[derive(Serialize)]
struct UnitStruct;

/// Newtype-struct content used to verify transparent unwrapping.
#[derive(Serialize)]
struct NewtypeStruct<T>(T);

/// Tuple-struct content that internal tagging must reject.
#[derive(Serialize)]
struct TupleStruct(u8, u8);

/// Nested enum shapes used to exercise variant-specific serializer entries.
#[derive(Serialize)]
enum NestedEnum {
    /// Unit variant accepted as a nested map entry.
    Unit,
    /// Newtype variant accepted as a nested map entry.
    Newtype(&'static str),
    /// Tuple variant rejected because it cannot carry the outer tag.
    Tuple(u8, u8),
    /// Struct variant rejected because it introduces nested tagging.
    Struct {
        /// Visible nested value.
        value: u8,
    },
}

/// Byte content that selects [`Serializer::serialize_bytes`].
struct Bytes<'a>(&'a [u8]);

impl Serialize for Bytes<'_> {
    /// Selects the byte-array serializer entry directly.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0)
    }
}

/// Map content that deliberately reports no length hint.
struct UnknownLengthMap;

impl Serialize for UnknownLengthMap {
    /// Emits one map entry without a size hint.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("visible", "value")?;
        map.end()
    }
}

/// Writer that fails once its byte allowance is exhausted.
struct FailAfter {
    /// Number of bytes still accepted.
    remaining: usize,
}

impl Write for FailAfter {
    /// Accepts at most the configured byte allowance.
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("intentional serializer failure"));
        }
        let accepted = self.remaining.min(buffer.len());
        self.remaining -= accepted;
        Ok(accepted)
    }

    /// Flushes successfully because only data writes are under test.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serializes one value through the internal-tag adapter into JSON.
fn internally_tagged<T>(value: &T) -> Result<Value, Error>
where
    T: Serialize + ?Sized,
{
    serialize_internally_tagged(
        ValueSerializer,
        "Event",
        "Payload",
        "kind",
        "Payload",
        value,
    )
}

/// Serializes one value through a writer with a finite byte allowance.
fn internally_tagged_with_limit<T>(
    value: &T,
    remaining: usize,
) -> Result<(), Error>
where
    T: Serialize + ?Sized,
{
    let mut serializer = serde_json::Serializer::new(FailAfter { remaining });
    serialize_internally_tagged(
        &mut serializer,
        "Event",
        "Payload",
        "kind",
        "Payload",
        value,
    )
}

/// Asserts that a value shape is rejected with a targeted diagnostic.
fn assert_unsupported<T>(value: &T, kind: &str)
where
    T: Serialize + ?Sized,
{
    let error = internally_tagged(value)
        .expect_err("the value shape cannot carry an internal tag");
    let message = error.to_string();

    assert!(message.contains("Event::Payload"));
    assert!(message.contains(kind));
}

/// Verifies the adapter merges the tag without exposing raw content.
#[test]
fn test_internally_tagged_serializer_merges_redacted_struct() {
    let value = Event::Payload(Payload {
        secret: String::from("raw-secret"),
    });

    let json = serde_json::to_value(value.redacted())
        .expect("map-like newtype content accepts an internal tag");

    assert_eq!(json["kind"], "Payload");
    assert!(!json.to_string().contains("raw-secret"));
}

/// Verifies every map-like or unit shape accepted by internal tagging.
#[test]
fn test_internally_tagged_serializer_accepts_supported_shapes() {
    let map = BTreeMap::from([("visible", "value")]);

    assert_eq!(
        internally_tagged(&map).expect("map content accepts an internal tag"),
        serde_json::json!({"kind": "Payload", "visible": "value"}),
    );
    assert_eq!(
        internally_tagged(&UnknownLengthMap)
            .expect("map content without a length hint accepts a tag"),
        serde_json::json!({"kind": "Payload", "visible": "value"}),
    );
    assert_eq!(
        internally_tagged(&()).expect("unit content accepts an internal tag"),
        serde_json::json!({"kind": "Payload"}),
    );
    assert_eq!(
        internally_tagged(&UnitStruct)
            .expect("unit-struct content accepts an internal tag"),
        serde_json::json!({"kind": "Payload"}),
    );
    assert_eq!(
        internally_tagged(&NestedEnum::Unit)
            .expect("unit-variant content accepts an internal tag"),
        serde_json::json!({"kind": "Payload", "Unit": null}),
    );
    assert_eq!(
        internally_tagged(&NestedEnum::Newtype("value"))
            .expect("newtype-variant content accepts an internal tag"),
        serde_json::json!({"kind": "Payload", "Newtype": "value"}),
    );
    assert_eq!(
        internally_tagged(&NewtypeStruct(map))
            .expect("newtype-struct content is transparently unwrapped"),
        serde_json::json!({"kind": "Payload", "visible": "value"}),
    );
}

/// Verifies every scalar, optional, and sequence shape fails closed.
#[test]
fn test_internally_tagged_serializer_rejects_unsupported_shapes() {
    assert_unsupported(&false, "a boolean");
    assert_unsupported(&1_i8, "an integer");
    assert_unsupported(&1_i16, "an integer");
    assert_unsupported(&1_i32, "an integer");
    assert_unsupported(&1_i64, "an integer");
    assert_unsupported(&1_u8, "an integer");
    assert_unsupported(&1_u16, "an integer");
    assert_unsupported(&1_u32, "an integer");
    assert_unsupported(&1_u64, "an integer");
    assert_unsupported(&1.0_f32, "a float");
    assert_unsupported(&1.0_f64, "a float");
    assert_unsupported(&'x', "a character");
    assert_unsupported("value", "a string");
    assert_unsupported(&Bytes(b"value"), "a byte array");
    assert_unsupported(&Option::<u8>::None, "an optional");
    assert_unsupported(&Some(1_u8), "an optional");
    assert_unsupported(&vec![1_u8], "a sequence");
    assert_unsupported(&(1_u8, 2_u8), "a tuple");
    assert_unsupported(&TupleStruct(1, 2), "a tuple struct");
    assert_unsupported(&NestedEnum::Tuple(1, 2), "a tuple variant");
    assert_unsupported(&NestedEnum::Struct { value: 1 }, "a struct variant");
}

/// Verifies destination failures propagate from every accepted compound
/// representation without exposing unredacted content.
#[test]
fn test_internally_tagged_serializer_propagates_writer_failures() {
    let map = BTreeMap::from([("visible", "value")]);
    let payload = Payload {
        secret: String::from("raw-secret"),
    };

    for remaining in 0..64 {
        let _ = internally_tagged_with_limit(&(), remaining);
        let _ = internally_tagged_with_limit(&NestedEnum::Unit, remaining);
        let _ = internally_tagged_with_limit(
            &NestedEnum::Newtype("value"),
            remaining,
        );
        let _ = internally_tagged_with_limit(&map, remaining);
        let _ = internally_tagged_with_limit(&payload, remaining);
    }

    assert!(internally_tagged_with_limit(&map, 128).is_ok());
}
