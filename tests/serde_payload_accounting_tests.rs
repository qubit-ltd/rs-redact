// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(all(feature = "derive", feature = "serde", feature = "json"))]

use std::collections::BTreeMap;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::domain::internal::BudgetSerialize;
use qubit_redact::domain::internal::RedactSerializeScope;
use serde::Serialize;
use serde::Serializer;

#[derive(Redact, Debug)]
#[redact(serde)]
struct Child {
    #[redact(level = "secret")]
    value: String,
}

#[derive(Redact)]
struct Parent {
    child: Child,
}

#[derive(Redact)]
struct Outer {
    #[redact(nested)]
    parent: Parent,
}

fn serialize_budgeted<T: Serialize>(value: &T, bytes: usize) -> serde_json::Result<serde_json::Value> {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_serde_payload_bytes(bytes);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let _scope = RedactSerializeScope::new(&policy);
    BudgetSerialize::new(value).serialize(serde_json::value::Serializer)
}

#[derive(Redact)]
struct ParentWithScalar {
    child: Child,
    extra: u8,
}

#[derive(Redact)]
struct ParentWithMap {
    child: Child,
    fields: BTreeMap<String, String>,
}

#[derive(Redact)]
#[redact(serde)]
struct ExplicitParent {
    #[redact(nested)]
    child: Child,
}

fn limited(bytes: usize) -> Redactor {
    Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_serde_payload_bytes(bytes);
            })
            .expect("valid limits")
            .build()
            .expect("valid policy"),
    )
}

fn parent() -> Parent {
    Parent {
        child: Child {
            value: "raw-secret".into(),
        },
    }
}

#[test]
fn test_ordinary_parent_charges_mask_once() {
    let parent = parent();
    assert!(limited(9).to_json(&parent).is_err());
    assert_eq!(limited(10).to_json(&parent.child).unwrap(), r#"{"value":"<redacted>"}"#);
    assert_eq!(
        limited(10).to_json(&parent).unwrap(),
        r#"{"child":{"value":"<redacted>"}}"#
    );
}

#[test]
fn test_multiple_ordinary_wrappers_charge_mask_once() {
    let outer = Outer { parent: parent() };
    assert_eq!(
        limited(10).to_json(&outer).unwrap(),
        r#"{"parent":{"child":{"value":"<redacted>"}}}"#
    );
}

#[test]
fn test_explicit_nested_child_charges_mask_once() {
    let value = ExplicitParent { child: parent().child };
    assert!(limited(9).to_json(&value).is_err());
    assert_eq!(
        limited(10).to_json(&value).unwrap(),
        r#"{"child":{"value":"<redacted>"}}"#
    );
}

#[test]
fn test_additional_scalar_still_uses_payload_budget() {
    let value = ParentWithScalar {
        child: parent().child,
        extra: 1,
    };
    assert!(limited(10).to_json(&value).is_err());
    assert!(limited(11).to_json(&value).is_ok());
}

#[test]
fn test_forwarding_credit_does_not_cover_dynamic_map_key() {
    let value = ParentWithMap {
        child: parent().child,
        fields: BTreeMap::from([("k".to_owned(), String::new())]),
    };
    assert!(limited(10).to_json(&value).is_err());
    assert!(limited(11).to_json(&value).is_ok());
}

#[test]
fn test_source_and_view_preserve_non_json_serde_events() {
    let source = parent().child;
    let redactor = limited(10);
    let tokens = [
        serde_test::Token::Struct { name: "Child", len: 1 },
        serde_test::Token::Str("value"),
        serde_test::Token::Str("<redacted>"),
        serde_test::Token::StructEnd,
    ];
    serde_test::assert_ser_tokens(&source, &tokens);
    serde_test::assert_ser_tokens(&redactor.redact_view(&source), &tokens);
}

#[test]
fn test_output_error_does_not_poison_the_next_budget() {
    let value = parent();
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_serde_payload_bytes(10).max_output_bytes(1);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    assert!(Redactor::new(policy).to_json(&value).is_err());
    assert_eq!(
        limited(10).to_json(&value).unwrap(),
        r#"{"child":{"value":"<redacted>"}}"#
    );
}

#[derive(Debug)]
struct CountingDisplay(AtomicUsize);

impl fmt::Display for CountingDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fetch_add(1, Ordering::SeqCst);
        f.write_str("x")
    }
}

#[derive(Debug)]
struct DisplayPayload<'a>(&'a CountingDisplay);

impl Serialize for DisplayPayload<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self.0)
    }
}

#[derive(Debug)]
struct CustomPayload(&'static str);

impl Serialize for CustomPayload {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

struct CountedPayload<'a>(&'a AtomicUsize);

impl Serialize for CountedPayload<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        serializer.serialize_str("x")
    }
}

#[derive(Serialize)]
struct DynamicKey {
    #[serde(flatten)]
    fields: BTreeMap<String, String>,
}

#[derive(Serialize)]
enum UnitChoice {
    Marker,
}

#[test]
fn test_custom_serialize_and_dynamic_key_are_budgeted() {
    assert!(serialize_budgeted(&CustomPayload("x"), 0).is_err());
    assert!(
        serialize_budgeted(
            &DynamicKey {
                fields: BTreeMap::from([("k".to_owned(), "".to_owned())]),
            },
            0
        )
        .is_err()
    );
    assert!(serialize_budgeted(&CustomPayload("x"), 1).is_ok());
    assert!(serialize_budgeted(&UnitChoice::Marker, 0).is_err());
    assert!(serialize_budgeted(&UnitChoice::Marker, 6).is_ok());
}

#[test]
fn test_custom_serialize_callback_runs_once_on_success_and_rejection() {
    let calls = AtomicUsize::new(0);
    assert!(serialize_budgeted(&CountedPayload(&calls), 0).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(serialize_budgeted(&CountedPayload(&calls), 1).is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn test_unwinding_during_view_serialization_does_not_poison_next_budget() {
    let value = parent().child;
    let redactor = limited(10);
    let wrong_tokens = [
        serde_test::Token::Struct { name: "Child", len: 1 },
        serde_test::Token::Str("value"),
        serde_test::Token::Str("incorrect"),
        serde_test::Token::StructEnd,
    ];
    let unwind = std::panic::catch_unwind(AssertUnwindSafe(|| {
        serde_test::assert_ser_tokens(&redactor.redact_view(&value), &wrong_tokens);
    }));
    assert!(unwind.is_err());
    assert_eq!(redactor.to_json(&value).unwrap(), r#"{"value":"<redacted>"}"#);
}

#[test]
fn test_collect_str_formats_once_and_charges_payload() {
    let value = CountingDisplay(AtomicUsize::new(0));
    assert!(serialize_budgeted(&DisplayPayload(&value), 0).is_err());
    assert_eq!(value.0.load(Ordering::SeqCst), 1);
    assert!(serialize_budgeted(&DisplayPayload(&value), 1).is_ok());
    assert_eq!(value.0.load(Ordering::SeqCst), 2);
}
