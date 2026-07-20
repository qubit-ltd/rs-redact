// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Passing fixture for a generic named-field struct.

use std::fmt::Debug;

use qubit_redact::Redact as RedactTrait;
use qubit_redact_derive::Redact;

/// A generic record that retains its original where clause.
#[derive(Redact)]
struct GenericRecord<T>
where
    T: Debug,
{
    /// Identifier formatted by its existing `Debug` implementation.
    id: T,
    /// Ordinary visible name.
    name: String,
}

/// Exercises the generated implementation through the runtime trait.
fn main() {
    let value = GenericRecord {
        id: 7_u64,
        name: "Alice".to_owned(),
    };
    assert_eq!(
        format!("{:?}", value.redacted()),
        "GenericRecord { id: 7, name: \"Alice\" }",
    );
}
