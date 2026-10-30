// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

#![cfg(all(feature = "derive", feature = "serde"))]

use std::marker::PhantomData;

use qubit_redact::Redact;
use qubit_redact::Redactor;
use serde::Serializer;
use serde_json::json;

fn encode<S: Serializer>(_: &PhantomData<Record>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_unit()
}

fn keep_marker(_: &PhantomData<Record>) -> bool {
    true
}

fn encode_generic<T, S: Serializer>(_: &PhantomData<Generic<T>>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_unit()
}

#[derive(Redact)]
#[redact(serde)]
struct Record {
    #[serde(serialize_with = "encode", skip_serializing_if = "keep_marker")]
    marker: PhantomData<Self>,
}

#[derive(Redact)]
#[redact(serde)]
struct Generic<T> {
    #[serde(serialize_with = "encode_generic")]
    marker: PhantomData<Self>,
    value: T,
}

#[derive(Redact)]
struct ViewOnly {
    #[serde(serialize_with = "encode_view")]
    marker: PhantomData<Self>,
}

fn encode_view<S: Serializer>(_: &PhantomData<ViewOnly>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_unit()
}

#[derive(Redact)]
#[redact(serde)]
struct Tuple(#[serde(serialize_with = "encode_tuple")] PhantomData<Self>);

fn encode_tuple<S: Serializer>(_: &PhantomData<Tuple>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_unit()
}

#[derive(Redact)]
#[redact(serde)]
enum Event {
    Tuple(#[serde(serialize_with = "encode_event")] PhantomData<Self>),
}

fn encode_event<S: Serializer>(_: &PhantomData<Event>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_unit()
}

#[test]
fn test_adapter_self_field_types_serialize_from_source_and_view() {
    assert_eq!(serde_json::to_value(Record { marker: PhantomData }).unwrap(), json!({}));
    assert_eq!(
        serde_json::to_value(Generic {
            marker: PhantomData,
            value: 7_u8
        })
        .unwrap(),
        json!({"marker": null, "value": 7})
    );
    let view = Redactor::standard().redact_view(&ViewOnly { marker: PhantomData });
    assert_eq!(serde_json::to_value(view).unwrap(), json!({"marker": null}));
    assert_eq!(serde_json::to_value(Tuple(PhantomData)).unwrap(), json!(null));
    assert_eq!(
        serde_json::to_value(Event::Tuple(PhantomData)).unwrap(),
        json!({"Tuple": null})
    );
}

#[cfg(feature = "json")]
#[test]
fn test_adapter_self_field_types_serialize_through_json_redactor() {
    let value = Record { marker: PhantomData };
    let output = Redactor::standard().to_json(&value).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&output).unwrap(), json!({}));
}
