// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Self-recursive borrowed projection regressions.

#![cfg(all(feature = "derive", feature = "serde", feature = "json"))]

use std::cell::Cell;
use std::io;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::domain::internal::RedactSerializeSource;
use qubit_redact::domain::internal::RedactedSerializeRef;
use serde::Serialize;

struct ArrayCallbackCounter<'a>(&'a Cell<usize>);

impl serde_json::ser::Formatter for ArrayCallbackCounter<'_> {
    fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        self.0.set(self.0.get() + 1);
        if first { Ok(()) } else { writer.write_all(b",") }
    }
}

fn serialize_with_array_counter<T: RedactSerializeSource>(
    redactor: &Redactor,
    value: &T,
    callbacks: &Cell<usize>,
) -> Result<String, serde_json::Error>
where
    for<'value> T::RedactedFields<'value>: serde::Serialize,
{
    let mut output = Vec::new();
    let formatter = ArrayCallbackCounter(callbacks);
    let mut serializer = serde_json::Serializer::with_formatter(&mut output, formatter);
    redactor.redact_view(value).serialize(&mut serializer)?;
    Ok(String::from_utf8(output).expect("JSON is UTF-8"))
}

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

#[allow(clippy::vec_box)]
#[derive(Redact)]
#[redact(crate = qubit_redact)]
struct BudgetNode {
    children: Vec<Box<BudgetNode>>,
}

#[derive(Redact)]
#[redact(crate = qubit_redact)]
struct OrdinaryVector {
    children: Vec<u8>,
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
fn test_recursive_vector_stops_when_container_node_is_rejected() {
    let value = BudgetNode {
        children: (0..1000).map(|_| Box::new(BudgetNode { children: vec![] })).collect(),
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1).max_nodes(1);
        })
        .unwrap()
        .build()
        .unwrap();
    let redactor = Redactor::new(policy);
    let encoded = redactor.to_json(&value).unwrap();
    assert_eq!(encoded, r#"{"children":"<redacted>"}"#);
    let view = serde_json::to_value(redactor.redact_view(&value)).unwrap();
    assert_eq!(view, serde_json::json!({"children":"<redacted>"}));
}

#[test]
fn test_recursive_vector_budget_matrix() {
    let make_value = |count: usize| BudgetNode {
        children: (0..count).map(|_| Box::new(BudgetNode { children: vec![] })).collect(),
    };
    let value = make_value(1000);
    let node_limited = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(2000).max_nodes(1);
        })
        .unwrap()
        .build()
        .unwrap();
    let redactor = Redactor::new(node_limited);
    let callbacks = Cell::new(0);
    let encoded = serialize_with_array_counter(&redactor, &value, &callbacks).unwrap();
    assert_eq!(encoded, r#"{"children":"<redacted>"}"#);
    assert_eq!(callbacks.get(), 0);

    let item_limited = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1).max_nodes(2000);
        })
        .unwrap()
        .build()
        .unwrap();
    let redactor = Redactor::new(item_limited);
    let callbacks = Cell::new(0);
    assert!(serialize_with_array_counter(&redactor, &value, &callbacks).is_err());
    assert_eq!(callbacks.get(), 0);

    for count in [0, 1, 1000] {
        let value = make_value(count);
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_collection_items(5000).max_nodes(5000);
            })
            .unwrap()
            .build()
            .unwrap();
        let redactor = Redactor::new(policy);
        let encoded = redactor.to_json(&value).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(parsed["children"].as_array().unwrap().len(), count);
        assert_eq!(value.children.len(), count);
    }

    let root_limited = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(5000).max_nodes(0);
        })
        .unwrap()
        .build()
        .unwrap();
    let callbacks = Cell::new(0);
    let encoded = serialize_with_array_counter(&Redactor::new(root_limited), &value, &callbacks).unwrap();
    assert_eq!(encoded, r#""<redacted>""#);
    assert_eq!(callbacks.get(), 0);

    let depth_limited = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(5000).max_nodes(5000).max_depth(1);
        })
        .unwrap()
        .build()
        .unwrap();
    let callbacks = Cell::new(0);
    let encoded = serialize_with_array_counter(&Redactor::new(depth_limited), &value, &callbacks).unwrap();
    assert_eq!(encoded, r#"{"children":"<redacted>"}"#);
    assert_eq!(callbacks.get(), 0);

    let ordinary = OrdinaryVector { children: vec![1, 2] };
    let low_items = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .unwrap()
        .build()
        .unwrap();
    assert!(serde_json::to_value(Redactor::new(low_items).redact_view(&ordinary)).is_err());

    let secret_value = RecursiveVecNode {
        password: "root-secret".into(),
        children: (0..1000)
            .map(|index| {
                Box::new(RecursiveVecNode {
                    password: format!("child-secret-{index}"),
                    children: vec![],
                })
            })
            .collect(),
    };
    let ample = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_collection_items(5000)
                .max_nodes(5000)
                .max_output_bytes(500_000);
        })
        .unwrap()
        .build()
        .unwrap();
    let encoded = Redactor::new(ample).to_json(&secret_value).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(parsed["children"].as_array().unwrap().len(), 1000);
    assert_eq!(parsed["password"], "<redacted>");
    assert!(!encoded.contains("root-secret"));
    assert!(!encoded.contains("child-secret"));
    assert_eq!(secret_value.password, "root-secret");
    assert_eq!(secret_value.children.len(), 1000);
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
