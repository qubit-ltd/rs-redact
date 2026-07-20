// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for an empty field attribute.

use qubit_redact_derive::Redact;

/// Invalid empty mode selection.
#[derive(Redact)]
struct Record {
    /// Must choose exactly one field mode.
    #[redact()]
    value: String,
}

/// Keeps the invalid type reachable.
fn main() {}
