// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for a custom serde serializer.

use qubit_redact_derive::Redact;

/// Custom serialization could bypass the redaction wrappers.
#[derive(Redact)]
#[redact(serde)]
struct Record {
    /// Unsupported custom serialization algorithm.
    #[serde(serialize_with = "serialize_secret")]
    secret: String,
}

/// Placeholder serializer path.
fn serialize_secret() {}

/// Keeps the invalid type reachable.
fn main() {}
