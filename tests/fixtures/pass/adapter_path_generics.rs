// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::fmt::Debug;
use std::marker::PhantomData;

use qubit_redact::Redact;
use qubit_redact::Redactor;

fn encode<T: Debug, const N: usize, S: serde::Serializer>(
    value: &u32,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let _ = PhantomData::<T>;
    serializer.serialize_u32(*value + N as u32)
}

#[derive(Redact)]
#[redact(serde)]
struct Message<T, U, const N: usize, V>
where
    T: Debug + Into<U>,
    U: Copy,
{
    #[serde(serialize_with = "encode::<T, N, _>")]
    value: u32,
    marker: PhantomData<(T, U, V)>,
}

fn main() {
    let source = Message::<u8, u16, 1, ()> {
        value: 41,
        marker: PhantomData,
    };
    let view = serde_json::to_value(Redactor::standard().redact_view(&source)).unwrap();
    let direct = serde_json::to_value(&source).unwrap();
    assert_eq!(view["value"], 42);
    assert_eq!(direct["value"], 42);
}
