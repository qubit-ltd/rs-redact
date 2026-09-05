// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for a union input.

use qubit_redact_derive::Redact;

/// Unsupported union shape.
#[derive(Redact)]
union Value {
    /// Integer representation.
    integer: u64,
    /// Floating representation.
    float: f64,
}

/// Keeps the invalid type reachable.
fn main() {}
