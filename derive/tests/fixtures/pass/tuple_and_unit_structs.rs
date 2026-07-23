// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-pass fixture for tuple and unit structs.

use qubit_redact_derive::{Redact, RedactMut};

/// Tuple fields support redaction controls by position.
#[derive(Redact, RedactMut)]
struct Pair(
    #[redact(level = "secret")] String,
    #[redact(skip)] String,
);

/// Unit structs generate no-op redaction implementations.
#[derive(Redact, RedactMut)]
struct Marker;

/// Keeps the supported types reachable.
fn main() {
    let _ = Pair(String::new(), String::new());
    let _ = Marker;
}
