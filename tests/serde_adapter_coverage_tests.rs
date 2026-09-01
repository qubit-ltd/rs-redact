// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Coverage of the hidden Serde adapter used by internally tagged derives.

#![cfg(feature = "serde")]

use std::collections::BTreeMap;

use qubit_redact::domain::internal::serialize_internally_tagged;
use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap;

/// A serializer input that explicitly selects `serialize_bytes`.
struct Bytes<'value>(&'value [u8]);

impl Serialize for Bytes<'_> {
    /// Serializes the borrowed bytes without converting them to a sequence.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

/// Map serializer input that emits keys and values in separate Serde calls.
struct SeparateMap;

impl Serialize for SeparateMap {
    /// Serializes one entry with `serialize_key` followed by `serialize_value`.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_key("value")?;
        map.serialize_value(&11_u8)?;
        map.end()
    }
}

#[derive(Serialize)]
struct UnitStruct;

#[derive(Serialize)]
struct NewtypeStruct(u8);

#[derive(Serialize)]
struct TupleStruct(u8, u8);

#[derive(Serialize)]
struct RecordStruct {
    value: u8,
}

#[derive(Serialize)]
enum UnsupportedShapes {
    Unit,
    Newtype(u8),
    Tuple(u8, u8),
    Struct { value: u8 },
}

/// Calls the adapter with a non-map shape and checks its stable fail-closed
/// error contract.
fn assert_unsupported<T: Serialize + ?Sized>(value: &T) {
    let error = serialize_internally_tagged(
        serde_json::value::Serializer,
        "Envelope",
        "Variant",
        "kind",
        "Variant",
        value,
    )
    .expect_err("non-map internally tagged payload must be rejected");
    assert!(error.to_string().contains("non-map value"));
}

/// Exercises every unsupported Serde shape so each adapter method keeps the
/// same fail-closed behavior.
#[test]
fn test_internally_tagged_adapter_rejects_every_non_map_serde_shape() {
    assert_unsupported(&true);
    assert_unsupported(&1_i8);
    assert_unsupported(&2_i16);
    assert_unsupported(&3_i32);
    assert_unsupported(&4_i64);
    assert_unsupported(&5_i128);
    assert_unsupported(&6_u8);
    assert_unsupported(&7_u16);
    assert_unsupported(&8_u32);
    assert_unsupported(&9_u64);
    assert_unsupported(&10_u128);
    assert_unsupported(&1.25_f32);
    assert_unsupported(&2.5_f64);
    assert_unsupported(&'x');
    assert_unsupported("text");
    assert_unsupported(&Bytes(b"bytes"));
    assert_unsupported(&Option::<u8>::None);
    assert_unsupported(&Some(1_u8));
    assert_unsupported(&());
    assert_unsupported(&UnitStruct);
    assert_unsupported(&UnsupportedShapes::Unit);
    assert_unsupported(&NewtypeStruct(1));
    assert_unsupported(&UnsupportedShapes::Newtype(1));
    assert_unsupported(&vec![1_u8]);
    assert_unsupported(&(1_u8, 2_u8));
    assert_unsupported(&TupleStruct(1, 2));
    assert_unsupported(&UnsupportedShapes::Tuple(1, 2));
    assert_unsupported(&UnsupportedShapes::Struct { value: 1 });
}

/// Verifies that both map and struct payloads receive the internal tag and
/// forward their entries to the underlying serializer.
#[test]
fn test_internally_tagged_adapter_injects_tag_into_maps_and_structs() {
    let map = BTreeMap::from([("value", 7_u8)]);
    let encoded_map = serialize_internally_tagged(
        serde_json::value::Serializer,
        "Envelope",
        "Variant",
        "kind",
        "Variant",
        &map,
    )
    .expect("map payload should accept an internal tag");
    let encoded_struct = serialize_internally_tagged(
        serde_json::value::Serializer,
        "Envelope",
        "Variant",
        "kind",
        "Variant",
        &RecordStruct { value: 9 },
    )
    .expect("struct payload should accept an internal tag");
    let encoded_separate_map = serialize_internally_tagged(
        serde_json::value::Serializer,
        "Envelope",
        "Variant",
        "kind",
        "Variant",
        &SeparateMap,
    )
    .expect("separate map calls should accept an internal tag");

    assert_eq!(encoded_map["kind"], "Variant");
    assert_eq!(encoded_map["value"], 7);
    assert_eq!(encoded_struct["kind"], "Variant");
    assert_eq!(encoded_struct["value"], 9);
    assert_eq!(encoded_separate_map["kind"], "Variant");
    assert_eq!(encoded_separate_map["value"], 11);
}
