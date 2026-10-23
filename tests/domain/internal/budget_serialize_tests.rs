// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Publicly constructible Serde shape contracts for resource-admitted values.

use qubit_redact::RedactionPolicy;
use qubit_redact::domain::internal::BudgetSerialize;
use qubit_redact::domain::internal::RedactSerializeScope;
use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap;

#[derive(Serialize)]
struct Newtype(u8);

#[derive(Serialize)]
struct TupleStruct(u8, u8);

#[derive(Serialize)]
struct Record {
    value: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    omitted: Option<u8>,
}

struct Bytes<'a>(&'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

struct SeparateMap;

impl Serialize for SeparateMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_key("value")?;
        map.serialize_value(&11_u8)?;
        map.end()
    }
}

struct EntryMap;

impl Serialize for EntryMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("entry", &12_u8)?;
        map.end()
    }
}

struct HumanReadable;

impl Serialize for HumanReadable {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str("human-readable")
        } else {
            serializer.serialize_u8(0)
        }
    }
}

struct CollectedDisplay;

impl std::fmt::Display for CollectedDisplay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("collected label")
    }
}

impl Serialize for CollectedDisplay {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Serialize)]
enum EnumShape {
    Unit,
    Newtype(u8),
    Tuple(u8, u8),
    Record {
        value: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        omitted: Option<u8>,
    },
}

/// Runs an ordinary Serde value through the active resource budget.
fn serialize_budgeted<T: Serialize>(value: &T) -> serde_json::Value {
    let policy = RedactionPolicy::standard();
    let _scope = RedactSerializeScope::new(&policy);
    BudgetSerialize::new(value)
        .serialize(serde_json::value::Serializer)
        .expect("value should serialize within the default budget")
}

/// Newtypes, tuple structs, byte strings, and compound entries retain their
/// ordinary Serde representation after budget admission.
#[test]
fn test_budget_serializer_forwards_serde_shapes() {
    assert_eq!(serialize_budgeted(&Newtype(7)), serde_json::json!(7));
    assert_eq!(serialize_budgeted(&TupleStruct(3, 5)), serde_json::json!([3, 5]));
    assert_eq!(serialize_budgeted(&Bytes(b"abc")), serde_json::json!([97, 98, 99]));
    assert_eq!(
        serialize_budgeted(&Record {
            value: 9,
            omitted: None
        }),
        serde_json::json!({"value": 9})
    );
    assert_eq!(serialize_budgeted(&SeparateMap), serde_json::json!({"value": 11}));
    assert_eq!(serialize_budgeted(&EntryMap), serde_json::json!({"entry": 12}));
    assert_eq!(serialize_budgeted(&Some(13_u8)), serde_json::json!(13));
    assert_eq!(serialize_budgeted(&Option::<u8>::None), serde_json::Value::Null);
    assert_eq!(serialize_budgeted(&HumanReadable), serde_json::json!("human-readable"));
    assert_eq!(
        serialize_budgeted(&CollectedDisplay),
        serde_json::json!("collected label")
    );
    assert_eq!(serialize_budgeted(&EnumShape::Unit), serde_json::json!("Unit"));
    assert_eq!(
        serialize_budgeted(&EnumShape::Newtype(13)),
        serde_json::json!({"Newtype": 13})
    );
    assert_eq!(
        serialize_budgeted(&EnumShape::Tuple(2, 3)),
        serde_json::json!({"Tuple": [2, 3]})
    );
    assert_eq!(
        serialize_budgeted(&EnumShape::Record {
            value: 17,
            omitted: None,
        }),
        serde_json::json!({"Record": {"value": 17}})
    );
}
