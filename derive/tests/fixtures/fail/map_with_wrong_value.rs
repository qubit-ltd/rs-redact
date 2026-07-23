// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for a non-string map value.

use std::collections::HashMap;

use qubit_redact_derive::Redact;

/// Invalid map value type.
#[derive(Redact)]
struct Metrics {
    /// Map redaction requires supported text values.
    #[redact(map)]
    values: HashMap<String, u64>,
}

/// Keeps the invalid type reachable.
fn main() {}
