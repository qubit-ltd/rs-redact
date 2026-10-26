// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Self-recursive borrowed projection regressions.

#![cfg(all(feature = "derive", feature = "serde", feature = "json"))]

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::domain::internal::RedactedSerializeRef;

#[derive(Redact)]
#[redact(crate = qubit_redact)]
struct RecursiveNode {
    #[redact(level = "secret")]
    password: String,
    next: Option<Box<RecursiveNode>>,
}

#[test]
fn test_recursive_view_serializes_without_source_serialize() {
    let value = RecursiveNode {
        password: "root-secret".into(),
        next: Some(Box::new(RecursiveNode {
            password: "child-secret".into(),
            next: None,
        })),
    };
    let redactor = Redactor::standard();
    let expected = serde_json::json!({
        "password": "<redacted>",
        "next": {"password": "<redacted>", "next": null},
    });
    let text = redactor.to_json(&value).expect("recursive JSON view");
    assert_eq!(serde_json::from_str::<serde_json::Value>(&text).unwrap(), expected);
    assert_eq!(serde_json::to_value(redactor.redact_view(&value)).unwrap(), expected);
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
enum RecursiveChoice {
    Leaf {
        #[redact(level = "secret")]
        password: String,
    },
    Branch {
        next: Option<Box<Self>>,
    },
}

#[derive(Redact)]
#[redact(crate = qubit_redact)]
struct BorrowedRecursiveNode<'a, T> {
    label: &'a str,
    #[redact(level = "secret")]
    password: T,
    next: Option<Box<BorrowedRecursiveNode<'a, T>>>,
}

#[allow(clippy::vec_box)]
#[derive(Redact)]
#[redact(crate = qubit_redact)]
struct RecursiveVecNode {
    #[redact(level = "secret")]
    password: String,
    children: Vec<Box<RecursiveVecNode>>,
}

#[test]
fn test_recursive_enum_view_matches_redacted_source_serialize() {
    let value = RecursiveChoice::Branch {
        next: Some(Box::new(RecursiveChoice::Leaf {
            password: "leaf-secret".into(),
        })),
    };
    let redactor = Redactor::standard();
    let expected = serde_json::json!({
        "Branch": { "next": { "Leaf": { "password": "<redacted>" } } }
    });
    let source =
        serde_json::to_value(RedactedSerializeRef::new(&value, redactor.policy())).expect("source serialization");
    let view = serde_json::to_value(redactor.redact_view(&value)).expect("view serialization");
    assert_eq!(source, expected);
    assert_eq!(view, expected);
}

#[test]
fn test_recursive_borrowed_generic_none_and_some_values() {
    let label = String::from("node");
    let none = BorrowedRecursiveNode {
        label: &label,
        password: "root-secret".to_owned(),
        next: None,
    };
    let some = BorrowedRecursiveNode {
        label: &label,
        password: "root-secret".to_owned(),
        next: Some(Box::new(BorrowedRecursiveNode {
            label: &label,
            password: "child-secret".to_owned(),
            next: None,
        })),
    };
    let redactor = Redactor::standard();
    let none_expected = serde_json::json!({
        "label": "node", "password": "<redacted>", "next": null
    });
    let some_expected = serde_json::json!({
        "label": "node", "password": "<redacted>",
        "next": {"label": "node", "password": "<redacted>", "next": null}
    });
    assert_eq!(
        serde_json::to_value(redactor.redact_view(&none)).expect("None view"),
        none_expected
    );
    assert_eq!(
        serde_json::to_value(redactor.redact_view(&some)).expect("Some view"),
        some_expected
    );
}

#[test]
fn test_recursive_vec_box_view_serializes_multiple_levels() {
    let value = RecursiveVecNode {
        password: "root-secret".into(),
        children: vec![Box::new(RecursiveVecNode {
            password: "child-secret".into(),
            children: vec![],
        })],
    };
    let redactor = Redactor::standard();
    let expected = serde_json::json!({
        "password": "<redacted>",
        "children": [{ "password": "<redacted>", "children": [] }]
    });
    assert_eq!(
        serde_json::to_value(redactor.redact_view(&value)).expect("recursive Vec view"),
        expected
    );
}

#[test]
fn test_recursive_view_masks_after_structural_budget_rejection() {
    let value = RecursiveNode {
        password: "root-secret".into(),
        next: None,
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(0);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let text = Redactor::new(policy)
        .to_json(&value)
        .expect("zero node budget uses the fail-closed marker");
    assert_eq!(text, "\"<redacted>\"");
    assert!(!text.contains("root-secret"));
}
