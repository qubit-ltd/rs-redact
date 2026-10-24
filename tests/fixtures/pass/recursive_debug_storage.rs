// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use std::collections::BTreeMap;
use std::rc::Rc;

use qubit_redact::Redact;
use qubit_redact::Redactor;

#[derive(Debug, Redact)]
pub struct Node {
    name: String,
    children: BTreeMap<String, Node>,
    shared: Option<Rc<Node>>,
    next: Option<Box<Node>>,
}

pub fn render() -> String {
    let leaf = Node {
        name: "leaf".to_owned(),
        children: BTreeMap::new(),
        shared: None,
        next: None,
    };
    let mut children = BTreeMap::new();
    children.insert("first".to_owned(), leaf);
    let value = Node {
        name: "root".to_owned(),
        children,
        shared: Some(Rc::new(Node {
            name: "shared".to_owned(),
            children: BTreeMap::new(),
            shared: None,
            next: None,
        })),
        next: Some(Box::new(Node {
            name: "boxed".to_owned(),
            children: BTreeMap::new(),
            shared: None,
            next: None,
        })),
    };
    Redactor::standard().redact_text(&value).text().as_str().to_owned()
}

fn main() {
    let _ = render();
}
