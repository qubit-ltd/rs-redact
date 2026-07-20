// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for an enum input.

use qubit_redact_derive::Redact;

/// Unsupported enum shape.
#[derive(Redact)]
enum Event {
    /// One variant.
    Ready,
}

/// Keeps the invalid type reachable.
fn main() {}
