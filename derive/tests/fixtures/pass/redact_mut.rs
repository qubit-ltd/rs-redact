// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for destructive derived redaction.

use std::collections::HashMap;

use qubit_redact::RedactMut as RedactMutTrait;
use qubit_redact_derive::RedactMut;

/// Owned fields supported by destructive redaction.
#[derive(RedactMut)]
struct Account {
    /// Explicitly sensitive text.
    #[redact(level = "secret")]
    password: String,
    /// Runtime-keyed metadata.
    #[redact(map)]
    metadata: HashMap<String, String>,
}

/// Exercises the generated implementation.
fn main() {
    let mut value = Account {
        password: "raw".to_owned(),
        metadata: HashMap::new(),
    };
    value.redact_in_place();
}
