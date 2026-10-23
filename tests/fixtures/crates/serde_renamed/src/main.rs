// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixture proving generated serde paths honor dependency aliases.

use qubit_redact_derive::Redact;

/// Record used to compile the generated redacted-serialization implementation.
#[derive(Redact)]
#[redact(serde)]
struct Record {
    /// Plain value.
    value: String,
}

/// Compiles the derived record as part of this dependency-alias fixture.
fn main() {}
