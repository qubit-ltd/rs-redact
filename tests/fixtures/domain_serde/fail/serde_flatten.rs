// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for unsupported serde flattening.

use std::collections::BTreeMap;

use qubit_redact_derive::Redact;

/// Flattening would change the generated redacted structure.
#[derive(Redact)]
#[redact(serde)]
struct Record {
    /// Unsupported structural transformation.
    #[serde(flatten)]
    values: BTreeMap<String, String>,
}

/// Keeps the invalid type reachable.
fn main() {}
