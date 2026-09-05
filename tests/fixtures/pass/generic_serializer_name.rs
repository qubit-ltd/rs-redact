// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for serializer-name collision avoidance.

use qubit_redact_derive::Redact;

/// Generic parameter deliberately matching the old generated serializer name.
#[derive(Redact)]
#[redact(serde)]
struct Collision<__QubitRedactSerializer> {
    /// Field omitted from all redacted representations.
    #[redact(skip)]
    marker: core::marker::PhantomData<__QubitRedactSerializer>,
}

/// Exercises serialization with a colliding user generic name.
fn main() {
    let value = Collision::<u8> {
        marker: core::marker::PhantomData,
    };
    let _ = serde_json::to_value(value).expect("serializer-name collision should compile");
}
