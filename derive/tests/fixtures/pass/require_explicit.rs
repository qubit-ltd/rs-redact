// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for explicit field modes.

use qubit_redact_derive::Redact;

/// Record whose every field has an explicit redaction mode.
#[derive(Redact)]
#[redact(require_explicit)]
struct ExplicitRecord {
    /// Explicitly visible field.
    #[redact(plain)]
    visible: String,
    /// Explicitly masked field.
    #[redact(level = "secret")]
    secret: String,
    /// Explicitly omitted field.
    #[redact(skip)]
    omitted: String,
}

fn main() {
    let _ = ExplicitRecord {
        visible: String::new(),
        secret: String::new(),
        omitted: String::new(),
    };
}
