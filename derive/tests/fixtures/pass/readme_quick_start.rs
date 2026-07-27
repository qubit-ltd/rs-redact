// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compiles the quick-start example published in the derive crate README.

use qubit_redact_derive::Redact;

/// Credentials whose password is redacted at the secret level.
#[derive(Redact)]
struct Credentials {
    /// Password protected by the generated redaction implementation.
    #[redact(level = "secret")]
    password: String,
}

/// Keeps the quick-start type reachable in the fixture crate.
fn main() {
    let _credentials = Credentials {
        password: String::from("raw-password"),
    };
}
