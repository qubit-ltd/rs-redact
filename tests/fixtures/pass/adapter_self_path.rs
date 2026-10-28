// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact_derive::Redact;
use serde::Serialize;

#[derive(Redact)]
#[redact(serde)]
struct Source<'a, T, const N: usize> {
    #[serde(serialize_with = "Self::encode::<Self, _>")]
    value: &'a T,
    #[serde(skip)]
    marker: [u8; N],
}

impl<'a, T, const N: usize> Source<'a, T, N> {
    fn encode<U, S>(_: &&'a T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_unit()
    }
}

#[derive(Serialize)]
struct Native<'a, T, const N: usize> {
    #[serde(serialize_with = "Native::<'a, T, N>::encode::<Native<'a, T, N>, _>")]
    value: &'a T,
    #[serde(skip)]
    marker: [u8; N],
}

impl<'a, T, const N: usize> Native<'a, T, N> {
    fn encode<U, S>(_: &&'a T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_unit()
    }
}

#[derive(Redact)]
#[redact(serde)]
struct TupleSource(#[serde(serialize_with = "Self::encode")] String);

impl TupleSource {
    fn encode<S>(_: &String, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_unit()
    }
}

#[derive(Redact)]
#[redact(serde)]
enum EnumSource {
    Named {
        #[serde(serialize_with = "Self::encode")]
        value: String,
    },
    Tuple(#[serde(serialize_with = "Self::encode")] String),
}

impl EnumSource {
    fn encode<S>(_: &String, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_unit()
    }
}

fn main() {
    let value = 1_u32;
    let _ = Source {
        value: &value,
        marker: [0; 3],
    };
    let _ = Native {
        value: &value,
        marker: [0; 3],
    };
    let _ = TupleSource("tuple".to_owned());
    let _ = EnumSource::Named {
        value: "named".to_owned(),
    };
    let _ = EnumSource::Tuple("tuple".to_owned());
}
