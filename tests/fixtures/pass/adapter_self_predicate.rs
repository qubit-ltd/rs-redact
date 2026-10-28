// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use qubit_redact_derive::Redact;
use serde::Serialize;

fn encode<T, S: serde::Serializer>(_: &Option<T>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_unit()
}

#[derive(Redact)]
#[redact(serde)]
struct Source<T> {
    #[serde(serialize_with = "encode::<T, _>", skip_serializing_if = "Self::empty")]
    value: Option<T>,
}

impl<T> Source<T> {
    fn empty(value: &Option<T>) -> bool {
        value.is_none()
    }
}

#[derive(Serialize)]
struct Native<T> {
    #[serde(
        serialize_with = "encode::<T, _>",
        skip_serializing_if = "Native::empty"
    )]
    value: Option<T>,
}

impl<T> Native<T> {
    fn empty(value: &Option<T>) -> bool {
        value.is_none()
    }
}

fn main() {
    let _ = Source::<u32> { value: None };
    let _ = Native::<u32> { value: None };
}
