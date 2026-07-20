// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for repeated field modes.

use qubit_redact_derive::Redact;

/// Invalid duplicate mode selection.
#[derive(Redact)]
struct Record {
    /// Skip may be selected only once.
    #[redact(skip)]
    #[redact(skip)]
    value: String,
}

/// Keeps the invalid type reachable.
fn main() {}
