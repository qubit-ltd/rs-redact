// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Requires the optional JSON runtime feature.

use qubit_redact_derive::Redact;

/// JSON fields require the runtime JSON support.
#[derive(Redact)]
struct Record {
    /// Stored JSON text.
    #[redact(json)]
    payload: String,
}

fn main() {}
