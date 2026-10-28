// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use std::marker::PhantomData;

use qubit_redact::Redact;
use qubit_redact::Redactor;
use serde::Serialize;

fn encode<C, S: serde::Serializer>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> {
    let _ = std::mem::size_of::<C>();
    serializer.serialize_u32(*value + 1)
}

#[derive(Redact)]
#[redact(serde)]
struct Record<'a, T, const N: usize> {
    #[serde(serialize_with = "encode::<Option<&Self>, _>")]
    value: u32,
    marker: PhantomData<(&'a (), T, [u8; N])>,
}

#[derive(Serialize)]
struct Native<'a, T, const N: usize> {
    #[serde(serialize_with = "encode::<Option<&Self>, _>")]
    value: u32,
    marker: PhantomData<(&'a (), T, [u8; N])>,
}

fn main() {
    let native = Native::<'static, u8, 1> {
        value: 41,
        marker: PhantomData,
    };
    let source = Record::<'static, u8, 1> {
        value: 41,
        marker: PhantomData,
    };
    let expected = serde_json::json!({"value": 42, "marker": null});
    assert_eq!(serde_json::to_value(&native).unwrap(), expected);
    assert_eq!(serde_json::to_value(&source).unwrap(), expected);

    let redactor = Redactor::standard();
    assert_eq!(
        serde_json::to_value(redactor.redact_view(&source)).unwrap(),
        expected
    );

    #[cfg(feature = "json")]
    {
        let encoded = redactor.to_json(&source).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).unwrap(),
            expected
        );
    }
}
