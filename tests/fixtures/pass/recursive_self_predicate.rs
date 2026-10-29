// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile contract for `Self` in predicates on recursive projections.

use qubit_redact::Redact;

#[derive(Redact)]
struct Node {
    #[serde(skip_serializing_if = "Self::empty")]
    label: String,
    next: Option<Box<Node>>,
}

impl Node {
    fn empty(value: &String) -> bool {
        value.is_empty()
    }
}

fn main() {
    let node = Node {
        label: String::new(),
        next: None,
    };
    let _view = qubit_redact::Redactor::standard().redact_view(&node);
}
