// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for a missing explicit field mode.

use qubit_redact_derive::Redact;

/// Record with a field that is missing its required explicit mode.
#[derive(Redact)]
#[redact(require_explicit)]
struct MissingMode {
    /// This field must be annotated with `#[redact(plain)]` or another mode.
    visible: String,
}

fn main() {}
