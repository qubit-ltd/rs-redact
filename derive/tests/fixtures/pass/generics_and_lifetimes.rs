// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for lifetimes, type parameters, const generics, and bounds.

use std::fmt::Debug;

use qubit_redact::{Redact as RedactTrait, RedactMut as RedactMutTrait};
use qubit_redact_derive::{Redact, RedactMut};

/// Marker with no formatting or redaction capabilities.
struct NoTraits;

/// Generic record preserving every user-supplied generic and where clause.
#[derive(Redact, RedactMut)]
struct GenericRecord<'a, T, const N: usize>
where
    T: Debug,
{
    /// Plain borrowed value requiring only the user's `Debug` bound.
    value: &'a T,
    /// Explicitly sensitive owned value.
    #[redact(level = "secret")]
    secret: String,
    /// Skipped generic data requiring no trait bound.
    #[redact(skip)]
    ignored: [NoTraits; N],
}

/// Exercises immutable and mutable generated implementations.
fn main() {
    let value = 7_u64;
    let mut record = GenericRecord::<_, 1> {
        value: &value,
        secret: "raw".to_owned(),
        ignored: [NoTraits],
    };
    let _ = &record.ignored;
    let _ = format!("{:?}", record.redacted());
    record.redact_in_place();
}
