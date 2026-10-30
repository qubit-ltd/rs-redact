// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::marker::PhantomData;

use qubit_redact::Redact;
use serde::Serializer;

#[derive(Redact)]
#[redact(serde)]
struct Record {
    #[serde(serialize_with = "encode")]
    marker: PhantomData<Self>,
}

fn encode<S: Serializer>(_: &PhantomData<Record>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_unit()
}

#[derive(Redact)]
#[redact(serde)]
struct Generic<T> {
    #[serde(serialize_with = "encode_generic")]
    marker: PhantomData<Self>,
    value: T,
}

fn encode_generic<T, S: Serializer>(_: &PhantomData<Generic<T>>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_unit()
}

fn main() {
    let record = Record { marker: PhantomData };
    let generic = Generic { marker: PhantomData, value: 7_u8 };
    assert_eq!(serde_json::to_value(record).unwrap(), serde_json::json!({"marker": null}));
    assert_eq!(serde_json::to_value(generic).unwrap(), serde_json::json!({"marker": null, "value": 7}));
}
