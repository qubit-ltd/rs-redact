// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for an unknown field attribute key.

use qubit_redact_derive::Redact;

/// Record containing a misspelled unsupported mode.
#[derive(Redact)]
struct Account {
    /// Invalid because `mask` does not identify an explicit sensitivity.
    #[redact(mask)]
    password: String,
}

/// Keeps the invalid type reachable by the compiler.
fn main() {}
