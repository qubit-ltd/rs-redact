// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for duplicate generated `Debug` implementations.

use qubit_redact_derive::Redact;

/// Invalid record deriving ordinary and redacted `Debug` together.
#[derive(Debug, Redact)]
#[redact(debug)]
struct Record {
    /// Plain value.
    value: String,
}

/// Keeps the invalid type reachable.
fn main() {}
