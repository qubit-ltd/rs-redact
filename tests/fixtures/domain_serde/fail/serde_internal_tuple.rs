// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for internally tagged tuple variants.

use qubit_redact_derive::Redact;

/// Internally tagged enum with structurally invalid tuple content.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum Event {
    /// Tuple variants cannot merge a tag field.
    Tuple(String, String),
}

/// Keeps the invalid type reachable.
fn main() {}
