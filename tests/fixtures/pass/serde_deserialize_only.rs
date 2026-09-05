// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for serialization-neutral Serde attributes.

use qubit_redact_derive::Redact;

/// Deserialization-only controls must not block redacted serialization.
#[derive(Redact)]
#[redact(serde)]
#[serde(default = "make_default", deny_unknown_fields)]
struct DeserializeOnlyRecord {
    /// A field with input compatibility controls.
    #[serde(default, alias = "legacy_value", skip_deserializing)]
    value: String,
}

fn main() {}
