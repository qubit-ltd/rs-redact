// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Pass fixture for supported nested containers.

use qubit_redact::Redact as RedactTrait;
use qubit_redact_derive::Redact;

/// Nested leaf.
#[derive(Redact)]
struct Leaf {
    /// Sensitive value.
    #[redact(level = "secret")]
    value: String,
}

/// Container combinations supported by nested redaction.
#[derive(Redact)]
struct Tree {
    /// Optional boxed leaf.
    #[redact(nested)]
    selected: Option<Box<Leaf>>,
    /// List of leaves.
    #[redact(nested)]
    leaves: Vec<Leaf>,
}

/// Exercises generated recursive formatting.
fn main() {
    let tree = Tree {
        selected: None,
        leaves: Vec::new(),
    };
    let _ = format!("{:?}", tree.redacted());
}
