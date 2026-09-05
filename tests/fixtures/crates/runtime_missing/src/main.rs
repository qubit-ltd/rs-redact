// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fixture proving each derive invocation requires the runtime dependency.

use qubit_redact_derive::Redact;

/// First derive without the required runtime.
#[derive(Redact)]
struct First {
    /// Plain value.
    value: String,
}

/// A second derive invocation keeps repeated diagnostics observable.
#[derive(Redact)]
struct Second {
    /// Owned value.
    value: String,
}

/// Keeps both invalid types reachable.
fn main() {}
