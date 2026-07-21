// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for nested redaction without serialization support.

use qubit_redact_derive::Redact;

/// Nested type that supports formatting but not redacted serialization.
#[derive(Redact)]
struct Child {
    /// Plain value.
    value: String,
}

/// Parent requesting redacted serialization.
#[derive(Redact)]
#[redact(serde)]
struct Parent {
    /// Requires the nested hidden serialization hook.
    #[redact(nested)]
    child: Child,
}

/// Keeps the invalid type reachable.
fn main() {}
