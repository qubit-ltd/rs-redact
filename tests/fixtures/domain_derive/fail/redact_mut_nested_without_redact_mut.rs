// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for nested destructive redaction capability.

use qubit_redact_derive::RedactMut;

/// Child without destructive redaction.
struct Child;

/// Parent requiring nested destructive redaction.
#[derive(RedactMut)]
struct Parent {
    /// Requires `Child: RedactMut`.
    #[redact(nested)]
    child: Child,
}

/// Keeps the invalid type reachable.
fn main() {}
