// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for map and skip conflict.

use std::collections::HashMap;

use qubit_redact_derive::Redact;

/// Invalid mixed field modes.
#[derive(Redact)]
struct Record {
    /// A field cannot be both omitted and processed as a map.
    #[redact(map, skip)]
    values: HashMap<String, String>,
}

/// Keeps the invalid type reachable.
fn main() {}
