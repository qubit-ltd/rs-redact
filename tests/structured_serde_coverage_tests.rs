// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Coverage of structured Serde capabilities consumed by generated code.

#![cfg(all(feature = "serde", feature = "json"))]

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::LinkedList;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::Arc;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::domain::internal::RedactLevelSerialize;
use qubit_redact::domain::internal::RedactSerialize;
use qubit_redact::domain::internal::RedactSerializeScope;
use qubit_redact::domain::internal::RedactedJsonSerializeRef;
use qubit_redact::domain::internal::RedactedLevelSerializeRef;
use qubit_redact::domain::internal::RedactedMapKeySerializeRef;
use qubit_redact::domain::internal::RedactedMapSerializeRef;
use qubit_redact::domain::internal::RedactedSerializeRef;
use serde::Serializer;

/// Minimal generated-like leaf used to exercise generic structured
/// containers.
struct StructuredLeaf(&'static str);

impl RedactSerialize for StructuredLeaf {
    /// Serializes the already safe test marker.
    fn serialize_redacted<S>(&self, serializer: S, _policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0)
    }
}

/// Serializes one explicit-level value through the adapter used by generated
/// implementations.
fn serialize_level<T: RedactLevelSerialize + ?Sized>(value: &T, policy: &RedactionPolicy) -> serde_json::Value {
    serde_json::to_value(RedactedLevelSerializeRef::new(value, policy, Sensitivity::Secret))
        .expect("level value should serialize")
}

/// Serializes one nested value through the adapter used by generated
/// implementations.
fn serialize_nested<T: RedactSerialize + ?Sized>(value: &T, policy: &RedactionPolicy) -> serde_json::Value {
    serde_json::to_value(RedactedSerializeRef::new(value, policy)).expect("nested value should serialize")
}

/// Exercises all recursive explicit-level Serde implementations.
#[test]
fn test_structured_level_serialization_covers_all_supported_containers() {
    let policy = RedactionPolicy::standard();
    let _scope = RedactSerializeScope::new(&policy);
    let deque = VecDeque::from([String::from("deque")]);
    let list = LinkedList::from([String::from("list")]);
    let heap = BinaryHeap::from([String::from("heap")]);
    let tree_set = BTreeSet::from([String::from("tree")]);
    let hash_set = HashSet::from([String::from("hash")]);
    let hash_map = HashMap::from([(String::from("key"), String::from("value"))]);
    let tree_map = BTreeMap::from([(String::from("key"), String::from("value"))]);
    let cow: Cow<'_, str> = Cow::Borrowed("cow");

    let values = [
        serialize_level(&Some(String::from("some")), &policy),
        serialize_level::<Option<String>>(&None, &policy),
        serialize_level(&vec![String::from("vec")], &policy),
        serialize_level(&deque, &policy),
        serialize_level(&list, &policy),
        serialize_level(&heap, &policy),
        serialize_level(&tree_set, &policy),
        serialize_level(&hash_set, &policy),
        serialize_level(&Box::new(String::from("box")), &policy),
        serialize_level(&Rc::new(String::from("rc")), &policy),
        serialize_level(&Arc::new(String::from("arc")), &policy),
        serialize_level(&hash_map, &policy),
        serialize_level(&tree_map, &policy),
        serialize_level(&[String::from("array")], &policy),
        serialize_level(&cow, &policy),
        serialize_level(&"borrowed", &policy),
        serialize_level(&(1_u8,), &policy),
        serialize_level(&(1_u8, 2_u8), &policy),
        serialize_level(&(1_u8, 2_u8, 3_u8), &policy),
        serialize_level(&(1_u8, 2_u8, 3_u8, 4_u8), &policy),
        serialize_level(&(1_u8, 2_u8, 3_u8, 4_u8, 5_u8), &policy),
        serialize_level(&(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8), &policy),
        serialize_level(&(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8), &policy),
        serialize_level(&(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8), &policy),
        serialize_level(&(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8), &policy),
        serialize_level(&(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8, 10_u8), &policy),
        serialize_level(
            &(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8, 10_u8, 11_u8),
            &policy,
        ),
        serialize_level(
            &(
                1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8, 10_u8, 11_u8, 12_u8,
            ),
            &policy,
        ),
    ];

    assert!(values.iter().all(|value| !value.to_string().contains("value")));
}

/// Exercises nested Option, sequence, array, and every tuple arity supported
/// by generated structured serialization.
#[test]
fn test_structured_nested_serialization_covers_all_supported_containers() {
    let policy = RedactionPolicy::standard();
    let _scope = RedactSerializeScope::new(&policy);
    let leaf = || StructuredLeaf("safe");

    let values = [
        serialize_nested(&Some(leaf()), &policy),
        serialize_nested::<Option<StructuredLeaf>>(&None, &policy),
        serialize_nested(&vec![leaf()], &policy),
        serialize_nested(&[leaf()], &policy),
        serialize_nested(&(leaf(),), &policy),
        serialize_nested(&(leaf(), leaf()), &policy),
        serialize_nested(&(leaf(), leaf(), leaf()), &policy),
        serialize_nested(&(leaf(), leaf(), leaf(), leaf()), &policy),
        serialize_nested(&(leaf(), leaf(), leaf(), leaf(), leaf()), &policy),
        serialize_nested(&(leaf(), leaf(), leaf(), leaf(), leaf(), leaf()), &policy),
        serialize_nested(&(leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf()), &policy),
        serialize_nested(
            &(leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf()),
            &policy,
        ),
        serialize_nested(
            &(leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf()),
            &policy,
        ),
        serialize_nested(
            &(
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
            ),
            &policy,
        ),
        serialize_nested(
            &(
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
            ),
            &policy,
        ),
        serialize_nested(
            &(
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
                leaf(),
            ),
            &policy,
        ),
    ];

    assert!(
        values
            .iter()
            .all(|value| value.is_null() || value.to_string().contains("safe"))
    );
}

/// Exercises every JSON text ownership form used by generated serializers.
#[test]
fn test_structured_json_serialization_covers_all_supported_text_forms() {
    let policy = RedactionPolicy::standard();
    let _scope = RedactSerializeScope::new(&policy);
    let owned = String::from(r#"{"password":"owned-secret"}"#);
    let borrowed = r#"{"password":"borrowed-secret"}"#;
    let cow: Cow<'_, str> = Cow::Borrowed(r#"{"password":"cow-secret"}"#);
    let values = [
        serde_json::to_value(RedactedJsonSerializeRef::new(&owned, &policy)).expect("owned JSON should serialize"),
        serde_json::to_value(RedactedJsonSerializeRef::new(borrowed, &policy)).expect("str JSON should serialize"),
        serde_json::to_value(RedactedJsonSerializeRef::new(&borrowed, &policy))
            .expect("borrowed JSON should serialize"),
        serde_json::to_value(RedactedJsonSerializeRef::new(&cow, &policy)).expect("cow JSON should serialize"),
        serde_json::to_value(RedactedJsonSerializeRef::new(&Some(owned), &policy))
            .expect("optional owned JSON should serialize"),
        serde_json::to_value(RedactedJsonSerializeRef::new(&Some(borrowed), &policy))
            .expect("optional borrowed JSON should serialize"),
        serde_json::to_value(RedactedJsonSerializeRef::new(&Some(cow), &policy))
            .expect("optional cow JSON should serialize"),
        serde_json::to_value(RedactedJsonSerializeRef::new(&Option::<String>::None, &policy))
            .expect("none JSON should serialize"),
    ];

    assert!(values.iter().all(|value| !value.to_string().contains("secret")));
}

/// Exercises policy-classified maps, explicit key masking, collision errors,
/// optional maps, and collection admission failure.
#[test]
fn test_structured_map_serialization_covers_map_modes_and_budget_failures() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("password");
        })
        .expect("field policy")
        .build()
        .expect("redaction policy");
    let hash = HashMap::from([
        (String::from("password"), String::from("raw-secret")),
        (String::from("public"), String::from("visible")),
    ]);
    let tree = BTreeMap::from([
        (String::from("password"), String::from("raw-secret")),
        (String::from("public"), String::from("visible")),
    ]);
    let _scope = RedactSerializeScope::new(&policy);

    let hash_value =
        serde_json::to_value(RedactedMapSerializeRef::new(&hash, &policy)).expect("hash map should serialize");
    let tree_value =
        serde_json::to_value(RedactedMapSerializeRef::new(&tree, &policy)).expect("tree map should serialize");
    let optional_hash = Some(hash.clone());
    let optional_tree = Some(tree.clone());
    let optional_hash_value = serde_json::to_value(RedactedMapSerializeRef::new(&optional_hash, &policy))
        .expect("optional hash map should serialize");
    let optional_tree_value = serde_json::to_value(RedactedMapSerializeRef::new(&optional_tree, &policy))
        .expect("optional tree map should serialize");
    let none_hash: Option<HashMap<String, String>> = None;
    let none_tree: Option<BTreeMap<String, String>> = None;
    let none_hash_value = serde_json::to_value(RedactedMapSerializeRef::new(&none_hash, &policy))
        .expect("none hash map should serialize");
    let none_tree_value = serde_json::to_value(RedactedMapSerializeRef::new(&none_tree, &policy))
        .expect("none tree map should serialize");

    assert_ne!(hash_value["password"], "raw-secret");
    assert_eq!(hash_value["public"], "visible");
    assert_eq!(tree_value, hash_value);
    assert_eq!(optional_hash_value, hash_value);
    assert_eq!(optional_tree_value, tree_value);
    assert!(none_hash_value.is_null());
    assert!(none_tree_value.is_null());

    let key_hash = HashMap::from([(String::from("first"), String::from("value"))]);
    let key_tree = BTreeMap::from([(String::from("second"), String::from("value"))]);
    let masked_hash = serde_json::to_value(RedactedMapKeySerializeRef::new(
        &key_hash,
        &policy,
        Sensitivity::Low,
        None,
    ))
    .expect("hash keys should serialize");
    let masked_tree = serde_json::to_value(RedactedMapKeySerializeRef::new(
        &key_tree,
        &policy,
        Sensitivity::Secret,
        Some(Sensitivity::Secret),
    ))
    .expect("tree keys and values should serialize");
    assert!(!masked_hash.to_string().contains("first"));
    assert!(!masked_tree.to_string().contains("second"));
    assert!(!masked_tree.to_string().contains("value"));

    drop(_scope);
    let collision = BTreeMap::from([
        (String::from("first"), String::from("one")),
        (String::from("second"), String::from("two")),
    ]);
    let _scope = RedactSerializeScope::new(&policy);
    let error = serde_json::to_value(RedactedMapKeySerializeRef::new(
        &collision,
        &policy,
        Sensitivity::Secret,
        None,
    ))
    .expect_err("opaque key masks must reject collisions");
    assert!(error.to_string().contains("collide"));

    drop(_scope);
    let limited_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(0);
        })
        .expect("limits")
        .build()
        .expect("limited policy");
    let _scope = RedactSerializeScope::new(&limited_policy);
    let rejected_map = serde_json::to_value(RedactedMapSerializeRef::new(&hash, &limited_policy))
        .expect("over-limit map should fail closed");
    assert_eq!(rejected_map, "<redacted>");
}

/// Exercises the collection-rejection branches shared by generated nested and
/// explicit-level serializers.
#[test]
fn test_structured_container_serialization_fails_closed_at_collection_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(0);
        })
        .expect("limits")
        .build()
        .expect("limited policy");
    let values = vec![String::from("raw-secret")];
    let nested = vec![StructuredLeaf("raw-secret")];
    let _scope = RedactSerializeScope::new(&policy);

    let level_value = serialize_level(&values, &policy);
    let nested_value = serialize_nested(&nested, &policy);

    assert_eq!(level_value, "<redacted>");
    assert_eq!(nested_value, "<redacted>");
}

/// Ensures hidden Serde adapters establish their own bounded scope when they
/// are invoked directly instead of through generated `Serialize` code.
#[test]
fn test_structured_map_adapters_enforce_limits_without_explicit_scope() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(0);
        })
        .expect("limits")
        .build()
        .expect("limited policy");
    let values = BTreeMap::from([(String::from("token"), String::from("raw-secret"))]);

    let classified = serde_json::to_value(RedactedMapSerializeRef::new(&values, &policy))
        .expect("direct map adapter should fail closed");
    let keyed = serde_json::to_value(RedactedMapKeySerializeRef::new(
        &values,
        &policy,
        Sensitivity::Secret,
        None,
    ))
    .expect("direct map-key adapter should fail closed");

    assert_eq!(classified, "<redacted>");
    assert_eq!(keyed, "<redacted>");
}

/// Ensures nested generated serialization cannot reset the budget owned by
/// its outer structured serialization.
#[test]
fn test_nested_structured_scope_preserves_the_outer_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limits")
        .build()
        .expect("limited policy");
    let values = BTreeMap::from([(String::from("token"), String::from("raw-secret"))]);
    let _outer_scope = RedactSerializeScope::new(&policy);

    let first = serde_json::to_value(RedactedMapKeySerializeRef::new(
        &values,
        &policy,
        Sensitivity::Secret,
        None,
    ))
    .expect("first map should consume the available item");
    let _nested_scope = RedactSerializeScope::new(&policy);
    let second = serde_json::to_value(RedactedMapKeySerializeRef::new(
        &values,
        &policy,
        Sensitivity::Secret,
        None,
    ))
    .expect("second map should fail closed");

    assert_ne!(first, "<redacted>");
    assert_eq!(second, "<redacted>");
}

/// Ensures an explicitly different nested policy owns an independent budget
/// instead of inheriting limits from an unrelated outer serialization.
#[test]
fn test_nested_structured_scope_uses_the_explicit_policy_budget() {
    let outer_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(8);
        })
        .expect("limits")
        .build()
        .expect("outer policy");
    let inner_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(1);
        })
        .expect("limits")
        .build()
        .expect("limited policy");
    let _outer_scope = RedactSerializeScope::new(&outer_policy);
    let first_outer = serde_json::to_value(RedactedLevelSerializeRef::new(&"abcd", &outer_policy, Sensitivity::Low))
        .expect("first outer value should consume its input budget");

    let inner = serde_json::to_value(RedactedLevelSerializeRef::new(
        &"abcdef",
        &inner_policy,
        Sensitivity::Low,
    ))
    .expect("inner value should fail closed under its own input limit");
    let second_outer = serde_json::to_value(RedactedLevelSerializeRef::new(
        &"efghij",
        &outer_policy,
        Sensitivity::Low,
    ))
    .expect("second outer value should resume the original outer budget");

    assert_ne!(first_outer, "<redacted>");
    assert_eq!(inner, "<redacted>");
    assert_eq!(second_outer, "<redacted>");
}

/// Domain leaf used to exercise the nested `Redact` container implementations.
struct DomainLeaf;

impl Redact for DomainLeaf {
    /// Writes a fixed safe marker.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("safe");
    }
}

/// Exercises nested domain containers and tuple arities through `Redactor`.
#[test]
fn test_nested_domain_redaction_covers_all_supported_container_shapes() {
    let redactor = Redactor::standard();
    let leaf = || DomainLeaf;
    macro_rules! assert_nested {
        ($value:expr) => {{
            let output = redactor.redact(&$value);
            assert!(output.text().as_str().contains("safe") || output.text().as_str() == "None");
        }};
    }

    assert_nested!(Some(leaf()));
    assert_nested!(Option::<DomainLeaf>::None);
    assert_nested!(Box::new(leaf()));
    assert_nested!(vec![leaf()]);
    assert_nested!([leaf()]);
    assert_nested!((leaf(),));
    assert_nested!((leaf(), leaf()));
    assert_nested!((leaf(), leaf(), leaf()));
    assert_nested!((leaf(), leaf(), leaf(), leaf()));
    assert_nested!((leaf(), leaf(), leaf(), leaf(), leaf()));
    assert_nested!((leaf(), leaf(), leaf(), leaf(), leaf(), leaf()));
    assert_nested!((leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf()));
    assert_nested!((leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf(),));
    assert_nested!((leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf(), leaf(),));
    assert_nested!((
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
    ));
    assert_nested!((
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
    ));
    assert_nested!((
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
        leaf(),
    ));
}
