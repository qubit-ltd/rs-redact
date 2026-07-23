// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixture proving both derives require the runtime dependency.

use qubit_redact_derive::{
    Redact,
    RedactMut,
};

/// Immutable derive without the required runtime.
#[derive(Redact)]
struct Immutable {
    /// Plain value.
    value: String,
}

/// Mutable derive without the required runtime.
#[derive(RedactMut)]
struct Mutable {
    /// Owned value.
    value: String,
}

/// Keeps both invalid types reachable.
fn main() {}
