// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for borrowed destructive redaction.

use qubit_redact_derive::RedactMut;

/// Borrowed text cannot be replaced in place.
#[derive(RedactMut)]
struct Borrowed<'a> {
    /// Must use an owned string or a custom mutation implementation.
    #[redact(level = "secret")]
    value: &'a str,
}

/// Keeps the invalid type reachable.
fn main() {}
