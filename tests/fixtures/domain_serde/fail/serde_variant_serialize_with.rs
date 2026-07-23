// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for a variant serializer bypass.

use qubit_redact_derive::Redact;

/// Enum attempting to bypass generated redaction at the variant boundary.
#[derive(Redact)]
#[redact(serde)]
enum Event {
    /// Custom variant serializers are not allowlisted.
    #[serde(serialize_with = "serialize_ready")]
    Ready,
}

/// Keeps the invalid type reachable.
fn main() {}
