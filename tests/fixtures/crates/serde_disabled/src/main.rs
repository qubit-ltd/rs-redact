// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixture proving redacted serde requires the runtime feature.

use qubit_redact_derive::Redact;

/// Invalid because the runtime dependency does not enable serde.
#[derive(Redact)]
#[redact(serde)]
struct Record {
    /// Plain value.
    value: String,
}

/// Keeps the invalid type reachable.
fn main() {}
