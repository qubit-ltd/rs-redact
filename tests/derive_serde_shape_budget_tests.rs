// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

#![cfg(all(feature = "derive", feature = "serde"))]

use qubit_redact::RedactionPolicy;
use qubit_redact::domain::internal::RedactSerialize;
use qubit_redact::domain::internal::RedactedSerializeRef;
use qubit_redact_derive::Redact;

#[derive(Redact)]
#[redact(serde)]
struct Record {
    a: u8,
    b: u8,
}
#[derive(Redact)]
#[redact(serde)]
struct Tuple(u8, u8);
#[derive(Redact)]
#[redact(serde)]
enum External {
    VeryLongVariant,
    Named { a: u8, b: u8 },
    Tuple(u8, u8),
}
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum Internal {
    VeryLongVariant,
    Named { a: u8, b: u8 },
}
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "data")]
enum Adjacent {
    VeryLongVariant,
    Named { a: u8, b: u8 },
    Tuple(u8, u8),
    Empty {},
}
#[derive(Redact)]
#[redact(serde)]
#[serde(untagged)]
enum Untagged {
    Named { a: u8, b: u8 },
    Tuple(u8, u8),
}

fn rejected<T: RedactSerialize>(value: &T, policy: &RedactionPolicy) {
    assert!(serde_json::to_value(RedactedSerializeRef::new(value, policy)).is_err());
}

/// Every emitted record or tuple slot shares the collection allowance.
#[test]
fn test_generated_containers_share_collection_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limits")
        .build()
        .expect("policy");
    rejected(&Record { a: 1, b: 2 }, &policy);
    rejected(&Tuple(1, 2), &policy);
    rejected(&External::Named { a: 1, b: 2 }, &policy);
    rejected(&External::Tuple(1, 2), &policy);
    rejected(&Internal::Named { a: 1, b: 2 }, &policy);
    rejected(&Adjacent::Named { a: 1, b: 2 }, &policy);
    rejected(&Adjacent::Tuple(1, 2), &policy);
    rejected(&Untagged::Named { a: 1, b: 2 }, &policy);
    rejected(&Untagged::Tuple(1, 2), &policy);
}

/// Variant names emitted as scalar values consume source and payload bytes.
#[test]
fn test_generated_variant_scalar_obeys_byte_budgets() {
    for output in [false, true] {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                if output {
                    limits.max_output_bytes(1);
                } else {
                    limits.max_input_bytes(1);
                }
            })
            .expect("limits")
            .build()
            .expect("policy");
        rejected(&External::VeryLongVariant, &policy);
        rejected(&Internal::VeryLongVariant, &policy);
        rejected(&Adjacent::VeryLongVariant, &policy);
    }
}

/// The adjacent content object itself is a node, even when it has no fields.
#[test]
fn test_adjacent_content_obeys_node_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    rejected(&Adjacent::Empty {}, &policy);
}

/// Adjacent payload slots also consume allowance after the two outer slots.
#[test]
fn test_adjacent_content_shares_collection_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(3);
        })
        .expect("limits")
        .build()
        .expect("policy");
    rejected(&Adjacent::Named { a: 1, b: 2 }, &policy);
    rejected(&Adjacent::Tuple(1, 2), &policy);
}

/// Exact admission preserves the successful ordinary representation.
#[test]
fn test_generated_shapes_preserve_wire_at_exact_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(2).max_input_bytes(2).max_output_bytes(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    assert_eq!(
        serde_json::to_value(RedactedSerializeRef::new(&Record { a: 1, b: 2 }, &policy)).expect("exact admission"),
        serde_json::json!({"a": 1, "b": 2})
    );
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(4).max_input_bytes(7).max_output_bytes(7);
        })
        .expect("limits")
        .build()
        .expect("policy");
    assert_eq!(
        serde_json::to_value(RedactedSerializeRef::new(&Adjacent::Named { a: 1, b: 2 }, &policy))
            .expect("exact admission"),
        serde_json::json!({"kind":"Named", "data":{"a":1,"b":2}})
    );
}
// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
