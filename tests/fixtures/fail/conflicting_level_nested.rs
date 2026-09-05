// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for level and nested conflict.

use qubit_redact_derive::Redact;

/// Invalid mixed field modes.
#[derive(Redact)]
struct Account {
    /// A field cannot have a fixed sensitivity and recursive redaction.
    #[redact(level = "secret", nested)]
    password: String,
}

/// Keeps the invalid type reachable.
fn main() {}
