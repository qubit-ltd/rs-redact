// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for mutually exclusive enum representations.

use qubit_redact_derive::Redact;

/// Enum requesting both internal tagging and no tag.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", untagged)]
enum Event {
    /// Unit variant.
    Ready,
}

/// Keeps the invalid type reachable.
fn main() {}
