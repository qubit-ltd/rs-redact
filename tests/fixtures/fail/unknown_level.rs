// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for a case-mismatched sensitivity level.

use qubit_redact_derive::Redact;

/// Record containing an invalid level spelling.
#[derive(Redact)]
struct Account {
    /// Invalid because sensitivity spellings are case-sensitive.
    #[redact(level = "Secret")]
    password: String,
}

/// Keeps the invalid type reachable by the compiler.
fn main() {}
