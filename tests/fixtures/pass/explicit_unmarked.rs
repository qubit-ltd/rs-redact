// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use qubit_redact::Redact;

#[derive(Redact)]
struct Node {
    name: String,
    #[redact(unmarked)]
    next: Option<Box<Self>>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ordinary-child")
    }
}

#[derive(Redact)]
struct PlainField {
    #[redact(unmarked)]
    value: String,
}

fn main() {
    let _ = Node {
        name: String::new(),
        next: None,
    };
    let _ = PlainField {
        value: String::new(),
    };
}
