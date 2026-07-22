// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixture proving generated serde paths honor dependency aliases.

use qubit_redact_derive::Redact;

/// Record with generated redacted serialization.
#[derive(Redact)]
#[redact(serde)]
struct Record {
    /// Plain value.
    value: String,
}

/// Keeps the derived type reachable.
fn main() {}
