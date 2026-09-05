// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for generic types nested in grouped syntax.

use qubit_redact_derive::Redact;

/// Generic record containing array and tuple fields.
#[derive(Redact)]
struct GroupedRecord<T, const N: usize> {
    #[redact(level = "secret")]
    array: [T; N],
    #[redact(level = "secret")]
    tuple: (T,),
}

/// Exercises recursive generic-parameter discovery inside groups.
fn main() {
    let value = GroupedRecord {
        array: ["array"; 2],
        tuple: ("tuple",),
    };
    let _ = value;
}
