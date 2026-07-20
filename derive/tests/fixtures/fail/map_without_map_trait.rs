// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for a non-map field in map mode.

use qubit_redact_derive::Redact;

/// Invalid map capability.
#[derive(Redact)]
struct Record {
    /// A vector does not expose string key/value map iteration.
    #[redact(map)]
    values: Vec<String>,
}

/// Keeps the invalid type reachable.
fn main() {}
