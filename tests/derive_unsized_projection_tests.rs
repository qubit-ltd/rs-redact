// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed derive support for unsized final fields.

#![cfg(feature = "derive")]

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Redact)]
pub struct Tail<T: ?Sized> {
    tail: T,
}

pub fn text(value: &Tail<str>) -> String {
    Redactor::standard().redact_text(value).text().as_str().to_owned()
}

pub fn bytes(value: &Tail<[u8]>) -> String {
    Redactor::standard().redact_text(value).text().as_str().to_owned()
}

#[cfg(feature = "serde")]
pub fn serialize_tail(value: &Tail<str>) -> serde_json::Value {
    serde_json::to_value(Redactor::standard().redact_view(value)).expect("supported unsized tail")
}

#[cfg(feature = "serde")]
pub fn serialize_bytes(value: &Tail<[u8]>) -> serde_json::Value {
    serde_json::to_value(Redactor::standard().redact_view(value)).expect("supported unsized bytes")
}

#[test]
fn test_unsized_text_and_view_functions_type_check() {
    let _: fn(&Tail<str>) -> String = text;
    let _: fn(&Tail<[u8]>) -> String = bytes;
    #[cfg(feature = "serde")]
    {
        let _: fn(&Tail<str>) -> serde_json::Value = serialize_tail;
        let _: fn(&Tail<[u8]>) -> serde_json::Value = serialize_bytes;
    }
}
