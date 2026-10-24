// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Coverage of the public sealed domain-value capabilities.

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
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// Exercises every scalar, recursive container, and tuple implementation used
/// by explicit level redaction.
struct LevelValues;

impl Redact for LevelValues {
    /// Writes each supported value through the public level-capable field API.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        let deque = VecDeque::from([String::from("deque-secret")]);
        let list = LinkedList::from([String::from("list-secret")]);
        let heap = BinaryHeap::from([String::from("heap-secret")]);
        let tree_set = BTreeSet::from([String::from("tree-secret")]);
        let hash_set = HashSet::from([String::from("hash-secret")]);
        let hash_map = HashMap::from([(String::from("key"), String::from("hash-map-secret"))]);
        let tree_map = BTreeMap::from([(String::from("key"), String::from("tree-map-secret"))]);
        let cow: Cow<'_, str> = Cow::Borrowed("cow-secret");
        let slice: &[String] = &[String::from("slice-secret")];

        writer.record("LevelValues", |fields| {
            fields
                .sensitive_value_exact(Sensitivity::Secret, "string", &String::from("string-secret"))
                .sensitive_value_exact(Sensitivity::Secret, "str", "str-secret")
                .sensitive_value_exact(Sensitivity::Secret, "cow", &cow)
                .sensitive_value_exact(Sensitivity::Secret, "char", &'x')
                .sensitive_value_exact(Sensitivity::Secret, "bool", &true)
                .sensitive_value_exact(Sensitivity::Secret, "i8", &1_i8)
                .sensitive_value_exact(Sensitivity::Secret, "i16", &2_i16)
                .sensitive_value_exact(Sensitivity::Secret, "i32", &3_i32)
                .sensitive_value_exact(Sensitivity::Secret, "i64", &4_i64)
                .sensitive_value_exact(Sensitivity::Secret, "i128", &5_i128)
                .sensitive_value_exact(Sensitivity::Secret, "isize", &6_isize)
                .sensitive_value_exact(Sensitivity::Secret, "u8", &7_u8)
                .sensitive_value_exact(Sensitivity::Secret, "u16", &8_u16)
                .sensitive_value_exact(Sensitivity::Secret, "u32", &9_u32)
                .sensitive_value_exact(Sensitivity::Secret, "u64", &10_u64)
                .sensitive_value_exact(Sensitivity::Secret, "u128", &11_u128)
                .sensitive_value_exact(Sensitivity::Secret, "usize", &12_usize)
                .sensitive_value_exact(Sensitivity::Secret, "f32", &1.25_f32)
                .sensitive_value_exact(Sensitivity::Secret, "f64", &2.5_f64)
                .sensitive_value_exact(Sensitivity::Secret, "some", &Some(String::from("some-secret")))
                .sensitive_value_exact::<Option<String>>(Sensitivity::Secret, "none", &None)
                .sensitive_value_exact(Sensitivity::Secret, "vec", &vec![String::from("vec-secret")])
                .sensitive_value_exact(Sensitivity::Secret, "slice", slice)
                .sensitive_value_exact(Sensitivity::Secret, "deque", &deque)
                .sensitive_value_exact(Sensitivity::Secret, "list", &list)
                .sensitive_value_exact(Sensitivity::Secret, "heap", &heap)
                .sensitive_value_exact(Sensitivity::Secret, "tree_set", &tree_set)
                .sensitive_value_exact(Sensitivity::Secret, "hash_set", &hash_set)
                .sensitive_value_exact(Sensitivity::Secret, "boxed", &Box::new(String::from("box-secret")))
                .sensitive_value_exact(Sensitivity::Secret, "rc", &Rc::new(String::from("rc-secret")))
                .sensitive_value_exact(Sensitivity::Secret, "arc", &Arc::new(String::from("arc-secret")))
                .sensitive_value_exact(Sensitivity::Secret, "hash_map", &hash_map)
                .sensitive_value_exact(Sensitivity::Secret, "tree_map", &tree_map)
                .sensitive_value_exact(Sensitivity::Secret, "array", &[String::from("array-secret")])
                .sensitive_value_exact(Sensitivity::Secret, "tuple1", &(1_u8,))
                .sensitive_value_exact(Sensitivity::Secret, "tuple2", &(1_u8, 2_u8))
                .sensitive_value_exact(Sensitivity::Secret, "tuple3", &(1_u8, 2_u8, 3_u8))
                .sensitive_value_exact(Sensitivity::Secret, "tuple4", &(1_u8, 2_u8, 3_u8, 4_u8))
                .sensitive_value_exact(Sensitivity::Secret, "tuple5", &(1_u8, 2_u8, 3_u8, 4_u8, 5_u8))
                .sensitive_value_exact(Sensitivity::Secret, "tuple6", &(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8))
                .sensitive_value_exact(
                    Sensitivity::Secret,
                    "tuple7",
                    &(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8),
                )
                .sensitive_value_exact(
                    Sensitivity::Secret,
                    "tuple8",
                    &(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8),
                )
                .sensitive_value_exact(
                    Sensitivity::Secret,
                    "tuple9",
                    &(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8),
                )
                .sensitive_value_exact(
                    Sensitivity::Secret,
                    "tuple10",
                    &(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8, 10_u8),
                )
                .sensitive_value_exact(
                    Sensitivity::Secret,
                    "tuple11",
                    &(1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8, 10_u8, 11_u8),
                )
                .sensitive_value_exact(
                    Sensitivity::Secret,
                    "tuple12",
                    &(
                        1_u8, 2_u8, 3_u8, 4_u8, 5_u8, 6_u8, 7_u8, 8_u8, 9_u8, 10_u8, 11_u8, 12_u8,
                    ),
                );
        });
    }
}

/// Exercises each supported map key ownership and optionality combination.
struct MapValues;

impl Redact for MapValues {
    /// Writes map-mode and explicit key-level values through public APIs.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        let owned_hash = HashMap::from([(String::from("password"), String::from("hash-secret"))]);
        let owned_tree = BTreeMap::from([(String::from("password"), String::from("tree-secret"))]);
        let borrowed_hash = HashMap::from([("password", String::from("borrowed-hash-secret"))]);
        let borrowed_tree = BTreeMap::from([("password", String::from("borrowed-tree-secret"))]);
        let cow_hash = HashMap::from([(Cow::Borrowed("password"), String::from("cow-hash-secret"))]);
        let cow_tree = BTreeMap::from([(Cow::Borrowed("password"), String::from("cow-tree-secret"))]);
        let key_level_hash = HashMap::from([(String::from("hash-key-secret"), String::from("visible"))]);
        let key_level_tree = BTreeMap::from([(String::from("tree-key-secret"), String::from("value-secret"))]);

        writer.record("MapValues", |fields| {
            fields
                .map_value("owned_hash", &owned_hash)
                .map_value("owned_tree", &owned_tree)
                .map_value("owned_hash_some", &Some(owned_hash.clone()))
                .map_value("owned_tree_some", &Some(owned_tree.clone()))
                .map_value::<Option<HashMap<String, String>>>("owned_hash_none", &None)
                .map_value::<Option<BTreeMap<String, String>>>("owned_tree_none", &None)
                .map_value("borrowed_hash", &borrowed_hash)
                .map_value("borrowed_tree", &borrowed_tree)
                .map_value("borrowed_hash_some", &Some(borrowed_hash.clone()))
                .map_value("borrowed_tree_some", &Some(borrowed_tree.clone()))
                .map_value::<Option<HashMap<&str, String>>>("borrowed_hash_none", &None)
                .map_value::<Option<BTreeMap<&str, String>>>("borrowed_tree_none", &None)
                .map_value("cow_hash", &cow_hash)
                .map_value("cow_tree", &cow_tree)
                .map_value("cow_hash_some", &Some(cow_hash.clone()))
                .map_value("cow_tree_some", &Some(cow_tree.clone()))
                .map_value::<Option<HashMap<Cow<'_, str>, String>>>("cow_hash_none", &None)
                .map_value::<Option<BTreeMap<Cow<'_, str>, String>>>("cow_tree_none", &None)
                .map_level_values("masked_hash_keys", &key_level_hash, Sensitivity::Secret, None)
                .map_level_values(
                    "masked_tree_keys",
                    &key_level_tree,
                    Sensitivity::Secret,
                    Some(Sensitivity::Secret),
                );
        });
    }
}

/// Exercises every supported JSON text ownership form.
struct JsonTextValues;

impl Redact for JsonTextValues {
    /// Writes JSON text values through the sealed public capability.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        let owned = String::from(r#"{"password":"owned-secret"}"#);
        let borrowed = r#"{"password":"borrowed-secret"}"#;
        let cow: Cow<'_, str> = Cow::Borrowed(r#"{"password":"cow-secret"}"#);
        writer.record("JsonTextValues", |fields| {
            fields
                .json_text_value("owned", &owned)
                .json_text_value("str", borrowed)
                .json_text_value("borrowed_ref", &borrowed)
                .json_text_value("cow", &cow)
                .json_text_value("some_owned", &Some(owned.clone()))
                .json_text_value("some_borrowed", &Some(borrowed))
                .json_text_value("some_cow", &Some(cow.clone()))
                .json_text_value::<Option<String>>("none_owned", &None)
                .json_text_value::<Option<&str>>("none_borrowed", &None)
                .json_text_value::<Option<Cow<'_, str>>>("none_cow", &None);
        });
    }
}

/// Verifies that all level-capable containers render without exposing their
/// raw marker strings.
#[test]
fn test_level_value_capabilities_cover_all_supported_container_shapes() {
    let output = Redactor::standard().redact_text(&LevelValues);
    let text = output.text().as_str();

    assert!(
        !text.contains("secret"),
        "level-capable values must not expose their raw marker strings",
    );
    assert!(
        text.contains("<redacted>"),
        "level-capable values must render the redaction marker",
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    for field in [
        "string", "str", "cow", "char", "bool", "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64",
        "u128", "usize", "f32", "f64", "some", "none", "vec", "slice", "deque", "list", "heap", "tree_set", "hash_set",
        "boxed", "rc", "arc", "hash_map", "tree_map", "array", "tuple1", "tuple2", "tuple3", "tuple4", "tuple5",
        "tuple6", "tuple7", "tuple8", "tuple9", "tuple10", "tuple11", "tuple12",
    ] {
        assert!(text.contains(&format!("{field}:")), "missing field {field}: {text}");
    }
    for arity in 1..=12 {
        let items = std::iter::repeat_n("\"<redacted>\"", arity)
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            text.contains(&format!("tuple{arity}: ({items})")),
            "wrong tuple{arity} shape: {text}"
        );
    }
    for (field, expected) in [
        ("some", "Some(\"<redacted>\")"),
        ("none", "None"),
        ("vec", "[\"<redacted>\"]"),
        ("slice", "[\"<redacted>\"]"),
        ("deque", "[\"<redacted>\"]"),
        ("list", "[\"<redacted>\"]"),
        ("heap", "[\"<redacted>\"]"),
        ("array", "[\"<redacted>\"]"),
    ] {
        assert!(
            text.contains(&format!("{field}: {expected}")),
            "unexpected {field} value: {text}"
        );
    }
}

/// Verifies that all supported map key forms preserve map shape while masking
/// sensitive entries.
#[test]
fn test_map_value_capabilities_cover_owned_borrowed_and_optional_maps() {
    let output = Redactor::standard().redact_text(&MapValues);
    let text = output.text().as_str();

    assert!(
        !text.contains("secret"),
        "map values and keys must not expose their raw marker strings",
    );
    assert!(
        text.contains("MapValues"),
        "the redacted map record must retain its outer structure",
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    for field in [
        "owned_hash",
        "owned_tree",
        "owned_hash_some",
        "owned_tree_some",
        "owned_hash_none",
        "owned_tree_none",
        "borrowed_hash",
        "borrowed_tree",
        "borrowed_hash_some",
        "borrowed_tree_some",
        "borrowed_hash_none",
        "borrowed_tree_none",
        "cow_hash",
        "cow_tree",
        "cow_hash_some",
        "cow_tree_some",
        "cow_hash_none",
        "cow_tree_none",
        "masked_hash_keys",
        "masked_tree_keys",
    ] {
        assert!(text.contains(&format!("{field}:")), "missing map field {field}: {text}");
    }
    for field in [
        "owned_hash_none",
        "owned_tree_none",
        "borrowed_hash_none",
        "borrowed_tree_none",
        "cow_hash_none",
        "cow_tree_none",
    ] {
        assert!(
            text.contains(&format!("{field}: None")),
            "missing None state for {field}: {text}"
        );
    }
}

/// Verifies that JSON text wrappers redact each ownership form and preserve a
/// structured field representation.
#[test]
fn test_json_value_capabilities_cover_owned_borrowed_and_optional_text() {
    let output = Redactor::standard().redact_text(&JsonTextValues);
    let text = output.text().as_str();

    assert!(
        !text.contains("secret"),
        "JSON text values must not expose their raw marker strings",
    );
    assert!(
        text.contains("JsonTextValues"),
        "the redacted JSON record must retain its outer structure",
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    for field in [
        "owned",
        "str",
        "borrowed_ref",
        "cow",
        "some_owned",
        "some_borrowed",
        "some_cow",
        "none_owned",
        "none_borrowed",
        "none_cow",
    ] {
        assert!(
            text.contains(&format!("{field}:")),
            "missing JSON field {field}: {text}"
        );
    }
    for field in ["some_owned", "some_borrowed", "some_cow"] {
        assert!(
            text.contains(&format!("{field}: \"{{\\\"password\\\":\\\"<redacted>\\\"}}\"")),
            "redacted JSON text was lost for {field}: {text}"
        );
    }
    for field in ["none_owned", "none_borrowed", "none_cow"] {
        assert!(
            text.contains(&format!("{field}: None")),
            "None state was lost for {field}: {text}"
        );
    }
}
