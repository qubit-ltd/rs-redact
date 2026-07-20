// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for a nested field lacking `Redact`.

use qubit_redact_derive::Redact;

/// Type that intentionally does not implement domain redaction.
struct Plain;

/// Invalid nested field.
#[derive(Redact)]
struct Wrapper {
    /// Requires a `Redact` implementation.
    #[redact(nested)]
    value: Plain,
}

/// Keeps the invalid type reachable.
fn main() {}
