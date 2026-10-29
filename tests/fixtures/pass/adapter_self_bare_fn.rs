// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use std::marker::PhantomData;

use qubit_redact::Redact;
use serde::Serialize;

trait Marker {}

impl Marker for fn(Record) {}
impl Marker for fn() -> Record {}
impl Marker for fn(SerdeRecord) {}
impl Marker for fn() -> SerdeRecord {}
impl<T> Marker for Option<fn(Generic<T>)> {}

fn encode<C: Marker, S: serde::Serializer>(
    value: &String,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

#[derive(Redact)]
#[redact(serde)]
struct Record {
    #[serde(serialize_with = "encode::<fn(Self), _>")]
    input: String,
    #[serde(serialize_with = "encode::<fn() -> Self, _>")]
    output: String,
}

#[derive(Serialize)]
struct SerdeRecord {
    #[serde(serialize_with = "encode::<fn(SerdeRecord), _>")]
    input: String,
    #[serde(serialize_with = "encode::<fn() -> SerdeRecord, _>")]
    output: String,
}

#[derive(Redact)]
#[redact(serde)]
struct Generic<T> {
    #[serde(serialize_with = "encode::<Option<fn(Self)>, _>")]
    value: String,
    #[serde(skip)]
    marker: PhantomData<T>,
}

fn main() {
    let record = Record {
        input: "one".into(),
        output: "two".into(),
    };
    let expected = serde_json::json!({"input": "one", "output": "two"});
    assert_eq!(serde_json::to_value(&record).unwrap(), expected);

    let serde_record = SerdeRecord {
        input: "one".into(),
        output: "two".into(),
    };
    assert_eq!(serde_json::to_value(&serde_record).unwrap(), expected);

    let redactor = qubit_redact::Redactor::standard();
    assert_eq!(
        serde_json::to_value(redactor.redact_view(&record)).unwrap(),
        expected
    );
    #[cfg(feature = "json")]
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&redactor.to_json(&record).unwrap()).unwrap(),
        expected
    );

    let generic = Generic::<u8> {
        value: "three".into(),
        marker: PhantomData,
    };
    let expected = serde_json::json!({"value": "three"});
    assert_eq!(serde_json::to_value(&generic).unwrap(), expected);
    assert_eq!(
        serde_json::to_value(redactor.redact_view(&generic)).unwrap(),
        expected
    );
}
