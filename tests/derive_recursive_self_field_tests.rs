// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

#![cfg(all(feature = "derive", feature = "serde"))]

use std::marker::PhantomData;

use qubit_redact::Redact;
use qubit_redact::Redactor;
use serde_json::json;
use serde_json::to_value;

#[derive(Redact)]
#[redact(serde)]
struct FunctionNode {
    #[redact(level = "secret")]
    password: String,
    next: Option<Box<Self>>,
    #[serde(skip)]
    callback: fn(&Self),
}

trait HasAssoc {
    type Assoc;
}

#[derive(Redact)]
#[redact(serde)]
struct AssociatedNode {
    #[redact(level = "secret")]
    password: String,
    next: Option<Box<Self>>,
    #[serde(skip)]
    marker: PhantomData<<Self as HasAssoc>::Assoc>,
}

impl HasAssoc for AssociatedNode {
    type Assoc = u8;
}

fn callback(_: &FunctionNode) {}

#[test]
fn test_recursive_skipped_function_self_type_serializes() {
    let child = FunctionNode {
        password: "child-secret".into(),
        next: None,
        callback,
    };
    let root = FunctionNode {
        password: "root-secret".into(),
        next: Some(Box::new(child)),
        callback,
    };
    // Read the skipped field so the regression does not introduce dead-code noise.
    (root.callback)(&root);
    let expected = json!({
        "password": "<redacted>",
        "next": {"password": "<redacted>", "next": null}
    });
    assert_eq!(to_value(&root).unwrap(), expected);
    assert_eq!(to_value(Redactor::standard().redact_view(&root)).unwrap(), expected);
    assert_eq!(root.password, "root-secret");
}

#[test]
fn test_recursive_skipped_qself_type_serializes() {
    let child = AssociatedNode {
        password: "child-secret".into(),
        next: None,
        marker: PhantomData,
    };
    let root = AssociatedNode {
        password: "root-secret".into(),
        next: Some(Box::new(child)),
        marker: PhantomData,
    };
    let expected = json!({
        "password": "<redacted>",
        "next": {"password": "<redacted>", "next": null}
    });
    assert_eq!(to_value(&root).unwrap(), expected);
    assert_eq!(to_value(Redactor::standard().redact_view(&root)).unwrap(), expected);
    assert_eq!(root.password, "root-secret");
}
