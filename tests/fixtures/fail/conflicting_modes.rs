// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for conflicting field modes.

use qubit_redact_derive::Redact;

/// Record selecting two mutually exclusive modes for one field.
#[derive(Redact)]
struct Account {
    /// Invalid because a field cannot be both masked and omitted.
    #[redact(level = "secret", skip)]
    password: String,
}

/// Keeps the invalid type reachable by the compiler.
fn main() {}
