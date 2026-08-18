// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for incremental domain traversal and input-free formatting.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::slice;

use qubit_redact::InputOutputLimit;
use qubit_redact::MaskingPolicy;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::domain::Redact;
use qubit_redact::domain::RedactValue;
use qubit_redact::domain::RedactedKeyedMap;
use qubit_redact::domain::RedactedMap;
use qubit_redact::domain::RedactedValue;
use qubit_redact::domain::RedactionWriter;
use qubit_redact::policy::DomainRedactionLimits;

/// Builds a policy with explicit domain and diagnostic limits.
fn policy_with_limits(
    max_nodes: usize,
    max_collection_items: usize,
    max_depth: usize,
    max_input_bytes: usize,
) -> RedactionPolicy {
    let domain = DomainRedactionLimits::builder()
        .max_nodes(max_nodes)
        .max_collection_items(max_collection_items)
        .max_depth(max_depth)
        .build()
        .expect("the test domain limits should be valid");
    let diagnostic = InputOutputLimit::builder()
        .max_input_bytes(max_input_bytes)
        .max_output_bytes(1024)
        .build()
        .expect("the test diagnostic limits should be valid");
    let mut builder = RedactionPolicy::builder();
    builder.limits().domain(domain).diagnostic_event(diagnostic);
    builder.build().expect("the test limits should build a policy")
}

/// Map-like value whose iterator records every call to `next`.
struct CountingMap<'value> {
    entries: &'value [(&'value str, &'value str)],
    next_calls: Cell<usize>,
}

/// Iterator that records access before delegating to the backing slice.
struct CountingIterator<'entry, 'value> {
    entries: slice::Iter<'entry, (&'value str, &'value str)>,
    next_calls: &'entry Cell<usize>,
}

impl<'entry, 'value> Iterator for CountingIterator<'entry, 'value> {
    type Item = (&'entry &'value str, &'entry &'value str);

    /// Records and returns the next map entry, if one remains.
    fn next(&mut self) -> Option<Self::Item> {
        self.next_calls.set(self.next_calls.get() + 1);
        self.entries.next().map(|entry| (&entry.0, &entry.1))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl ExactSizeIterator for CountingIterator<'_, '_> {
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<'entry, 'value> IntoIterator for &'entry CountingMap<'value> {
    type Item = (&'entry &'value str, &'entry &'value str);
    type IntoIter = CountingIterator<'entry, 'value>;

    /// Creates a counting iterator without advancing it.
    fn into_iter(self) -> Self::IntoIter {
        CountingIterator {
            entries: self.entries.iter(),
            next_calls: &self.next_calls,
        }
    }
}

/// Debug value that proves an unadmitted field was accessed by panicking.
struct PanicDebug;

impl fmt::Debug for PanicDebug {
    /// Panics whenever an unadmitted value reaches user formatting.
    fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("an unadmitted domain value must not be formatted")
    }
}

/// Object whose second field is blocked by a node limit.
struct NodeGuarded {
    safe: &'static str,
    blocked: PanicDebug,
}

impl Redact for NodeGuarded {
    /// Formats only fields admitted by the shared node budget.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.record("NodeGuarded", |fields| {
            fields.field("safe", || self.safe);
            fields.field("blocked", || &self.blocked);
        });
    }
}

/// Nested child that must not be entered when depth is limited to one.
struct DepthChild {
    blocked: PanicDebug,
}

impl Redact for DepthChild {
    /// Formats the child only after its value and field are both admitted.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.record("DepthChild", |fields| {
            fields.field("blocked", || &self.blocked);
        });
    }
}

/// Parent that continues with a sibling after a nested depth rejection.
struct DepthParent {
    child: DepthChild,
    sibling: &'static str,
}

impl Redact for DepthParent {
    /// Formats each admitted field with the same nested session.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.record("DepthParent", |fields| {
            fields.nested("child", &self.child);
            fields.field("sibling", || self.sibling);
        });
    }
}

/// Observer that captures input budget before and after pure domain work.
struct InputBudgetObserver<'state> {
    remaining: &'state Cell<Option<(usize, usize)>>,
}

/// Small recursively redacted value used by collection regressions.
#[derive(Debug)]
struct CollectionValue(&'static str);

impl Redact for CollectionValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.text(self.0);
    }
}

impl RedactValue for CollectionValue {
    fn redact_value<'a>(&'a self, level: Sensitivity, masking: &MaskingPolicy) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

/// Parent proving exact collection exhaustion does not close siblings.
struct ExactCollectionParent {
    values: Vec<CollectionValue>,
}

/// Parent proving an exact plain map does not close its sibling.
struct ExactPlainMapParent<'value> {
    map: CountingMap<'value>,
    tail: Vec<CollectionValue>,
}

impl Redact for ExactPlainMapParent<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.record("ExactPlainMapParent", |fields| {
            fields.map("map", &self.map);
            fields.nested("tail", &self.tail);
            fields.field("sibling", || "visible");
        });
    }
}

/// Keyed map whose exact iterator counts calls to `next`.
struct CountingKeyedMap<'value> {
    entries: &'value [(&'value str, CollectionValue)],
    next_calls: Cell<usize>,
}

/// Exact keyed iterator that counts calls to `next`.
struct CountingKeyedIterator<'entry, 'value> {
    entries: slice::Iter<'entry, (&'value str, CollectionValue)>,
    next_calls: &'entry Cell<usize>,
}

impl<'entry, 'value> Iterator for CountingKeyedIterator<'entry, 'value> {
    type Item = (&'entry &'value str, &'entry CollectionValue);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_calls.set(self.next_calls.get() + 1);
        self.entries.next().map(|entry| (&entry.0, &entry.1))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl ExactSizeIterator for CountingKeyedIterator<'_, '_> {
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<'entry, 'value> IntoIterator for &'entry CountingKeyedMap<'value> {
    type Item = (&'entry &'value str, &'entry CollectionValue);
    type IntoIter = CountingKeyedIterator<'entry, 'value>;

    fn into_iter(self) -> Self::IntoIter {
        CountingKeyedIterator {
            entries: self.entries.iter(),
            next_calls: &self.next_calls,
        }
    }
}

/// Parent proving an exact keyed map does not close its sibling.
struct ExactKeyedMapParent<'value> {
    map: CountingKeyedMap<'value>,
    tail: Vec<CollectionValue>,
}

impl Redact for ExactKeyedMapParent<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.record("ExactKeyedMapParent", |fields| {
            fields.map("map", &self.map);
            fields.nested("tail", &self.tail);
            fields.field("sibling", || "visible");
        });
    }
}

impl Redact for ExactCollectionParent {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.record("ExactCollectionParent", |fields| {
            fields.nested("values", &self.values);
            fields.field("sibling", || "visible");
        });
    }
}

/// Collection item with one depth-limited branch and one visible sibling.
#[derive(Debug)]
enum DepthCollectionValue {
    Deep,
    Visible,
}

impl Redact for DepthCollectionValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        match self {
            Self::Deep => {
                writer.tuple("Deep", |fields| {
                    fields.nested("", &DepthChild { blocked: PanicDebug });
                });
            }
            Self::Visible => writer.unit("Visible"),
        }
    }
}

impl RedactValue for DepthCollectionValue {
    fn redact_value<'a>(&'a self, level: Sensitivity, masking: &MaskingPolicy) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

/// Keyed value that panics if policy resolution reaches user redaction.
struct PanicKeyedValue;

impl Redact for PanicKeyedValue {
    fn write_redacted(&self, _writer: &mut RedactionWriter<'_, '_>) {
        panic!("an unadmitted keyed value must not invoke Redact")
    }
}

impl RedactValue for PanicKeyedValue {
    fn redact_value<'a>(&'a self, _level: Sensitivity, _masking: &MaskingPolicy) -> RedactedValue<'a> {
        panic!("an unadmitted keyed value must not invoke RedactValue")
    }
}

/// Parent that invokes the standalone keyed result inside an active depth.
struct NestedStandaloneKeyed;

impl Redact for NestedStandaloneKeyed {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.literal("<truncated>");
    }
}

/// Domain value that invokes JSON and environment adapters in an output frame.
#[cfg(feature = "json")]
struct NestedAdapterObserver<'state> {
    remaining: &'state Cell<Option<(usize, usize, usize)>>,
    json: &'static str,
}

#[cfg(feature = "json")]
impl Redact for NestedAdapterObserver<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        let before = writer.session().remaining_input_bytes();
        let json = writer.session().json_with_mut(|json| json.redact_text(self.json));
        let after_json = writer.session().remaining_input_bytes();
        let env = writer.session().env_with_mut(|env| env.redact_pair("NAME", "visible"));
        let after_env = writer.session().remaining_input_bytes();
        self.remaining.set(Some((before, after_json, after_env)));
        writer.text(&format!("{json}|{env}"));
    }
}

impl Redact for InputBudgetObserver<'_> {
    /// Records that domain admission and formatting leave input unchanged.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        let before = writer.session().remaining_input_bytes();
        let after = writer.session().remaining_input_bytes();
        self.remaining.set(Some((before, after)));
        writer.literal("InputBudgetObserver");
    }
}

/// Verifies collection admission happens before the next iterator access.
#[test]
fn test_collection_item_limit_stops_before_advancing_iterator() {
    let map = CountingMap {
        entries: &[("first", "one"), ("second", "two")],
        next_calls: Cell::new(0),
    };
    let policy = policy_with_limits(8, 1, 8, 64);

    let output = format!("{:?}", RedactedMap::new(&map, policy));

    assert_eq!(map.next_calls.get(), 1);
    assert!(output.contains("first"), "{output}");
    assert!(!output.contains("second"), "{output}");
    assert!(output.contains("<truncated>"), "{output}");
}

/// Verifies an unadmitted field never reaches its `Debug` implementation.
#[test]
fn test_node_limit_does_not_format_unadmitted_field() {
    let value = NodeGuarded {
        safe: "visible",
        blocked: PanicDebug,
    };
    let policy = policy_with_limits(2, 8, 8, 64);

    assert_eq!(
        format!("{:?}", value.redacted_with(&policy)),
        r#"NodeGuarded { safe: "visible", ...: <truncated> }"#,
    );
}

/// Verifies depth rejection truncates one branch and preserves its sibling.
#[test]
fn test_depth_limit_marks_nested_branch_and_preserves_sibling() {
    let value = DepthParent {
        child: DepthChild { blocked: PanicDebug },
        sibling: "visible",
    };
    let policy = policy_with_limits(8, 8, 1, 64);

    assert_eq!(
        format!("{:?}", value.redacted_with(&policy)),
        r#"DepthParent { child: <truncated>, sibling: "visible" }"#,
    );
}

/// Verifies pure domain formatting never consumes diagnostic input budget.
#[test]
fn test_domain_formatting_preserves_input_budget() {
    let remaining = Cell::new(None);
    let value = InputBudgetObserver { remaining: &remaining };
    let policy = policy_with_limits(8, 8, 8, 17);

    assert_eq!(format!("{:?}", value.redacted_with(&policy)), "InputBudgetObserver",);
    assert_eq!(remaining.get(), Some((17, 17)));
}

/// Exact collection limits must not emit a false trailing marker.
#[test]
fn test_exact_full_vec_does_not_emit_truncation_or_close_parent() {
    let value = ExactCollectionParent {
        values: vec![CollectionValue("first"), CollectionValue("second")],
    };
    let policy = policy_with_limits(16, 2, 8, 64);

    let output = format!("{:?}", value.redacted_with(&policy));

    assert!(!output.contains("<truncated>"), "{output}");
    assert!(output.contains("sibling: \"visible\""), "{output}");
}

/// Exact map limits must not emit a false trailing marker.
#[test]
fn test_exact_full_plain_map_does_not_emit_truncation() {
    let entries = [("first", "one"), ("second", "two")];
    let value = ExactPlainMapParent {
        map: CountingMap {
            entries: &entries,
            next_calls: Cell::new(0),
        },
        tail: vec![CollectionValue("tail")],
    };
    let policy = policy_with_limits(16, 3, 8, 64);
    let iterator = (&value.map).into_iter();
    assert_eq!(iterator.size_hint(), (2, Some(2)));
    assert_eq!(iterator.len(), 2);

    let output = format!("{:?}", value.redacted_with(&policy));

    assert!(!output.contains("<truncated>"), "{output}");
    assert!(output.contains("first"), "{output}");
    assert!(output.contains("second"), "{output}");
    assert!(output.contains("tail: [tail]"), "{output}");
    assert!(output.contains("sibling: \"visible\""), "{output}");
    assert_eq!(value.map.next_calls.get(), 2);
}

/// Exact keyed-map limits must not emit a false trailing marker.
#[test]
fn test_exact_full_keyed_map_does_not_emit_truncation() {
    let entries = [("first", CollectionValue("one")), ("second", CollectionValue("two"))];
    let value = ExactKeyedMapParent {
        map: CountingKeyedMap {
            entries: &entries,
            next_calls: Cell::new(0),
        },
        tail: vec![CollectionValue("tail")],
    };
    let policy = policy_with_limits(16, 3, 8, 64);
    let iterator = (&value.map).into_iter();
    assert_eq!(iterator.size_hint(), (2, Some(2)));
    assert_eq!(iterator.len(), 2);

    let output = format!("{:?}", value.redacted_with(&policy));

    assert!(!output.contains("<truncated>"), "{output}");
    assert!(output.contains("first"), "{output}");
    assert!(output.contains("second"), "{output}");
    assert!(output.contains("tail: [tail]"), "{output}");
    assert!(output.contains("sibling: \"visible\""), "{output}");
    assert_eq!(value.map.next_calls.get(), 2);
}

/// Keyed maps reuse collection admission instead of charging a standalone root.
#[test]
fn test_keyed_map_item_avoids_standalone_structural_double_charge() {
    let map = BTreeMap::from([("password", CollectionValue("secret"))]);
    let mut builder = RedactionPolicy::builder();
    builder
        .edit_fields()
        .raise("password", Sensitivity::Secret)
        .expect("the key rule should be valid");
    builder.limits().domain(
        DomainRedactionLimits::builder()
            .max_nodes(1)
            .max_collection_items(1)
            .max_depth(8)
            .build()
            .expect("the domain limits should be valid"),
    );
    let policy = builder.build().expect("the policy should be valid");

    let output = format!("{:?}", RedactedKeyedMap::new(&map, policy));

    assert_eq!(output, r#"{"password": "<redacted>"}"#);
}

/// A depth marker in one vector item must not terminate its siblings.
#[test]
fn test_vec_depth_marker_preserves_later_sibling() {
    let values = vec![DepthCollectionValue::Deep, DepthCollectionValue::Visible];
    let policy = policy_with_limits(16, 8, 2, 64);

    let output = format!("{:?}", values.redacted_with(&policy));

    assert!(output.contains("Deep(<truncated>)"), "{output}");
    assert!(output.contains("Visible"), "{output}");
}

/// A depth marker in one keyed-map value must not terminate later entries.
#[test]
fn test_keyed_map_depth_marker_preserves_later_sibling() {
    let map = BTreeMap::from([
        ("a_deep", DepthCollectionValue::Deep),
        ("b_visible", DepthCollectionValue::Visible),
    ]);
    let policy = policy_with_limits(16, 8, 2, 64);

    let output = format!("{:?}", RedactedKeyedMap::new(&map, policy));

    assert!(output.contains("Deep(<truncated>)"), "{output}");
    assert!(output.contains("b_visible"), "{output}");
    assert!(output.contains("Visible"), "{output}");
}

/// Standalone keyed values charge their root and field before resolution.
#[test]
fn test_standalone_keyed_node_limit_prevents_value_access() {
    let mut builder = RedactionPolicy::builder();
    builder
        .edit_fields()
        .raise("password", Sensitivity::Secret)
        .expect("the key rule should be valid");
    builder.limits().domain(
        DomainRedactionLimits::builder()
            .max_nodes(1)
            .max_collection_items(8)
            .max_depth(8)
            .build()
            .expect("the domain limits should be valid"),
    );
    let policy = builder.build().expect("the policy should be valid");
    let value = PanicKeyedValue;

    let output = format!("{:?}", Redactor::new(policy).redact_keyed("password", &value),);

    assert_eq!(output, "<truncated>");
}

/// Standalone keyed values reject a nested root before policy resolution.
#[test]
fn test_standalone_keyed_depth_limit_prevents_value_access() {
    let mut builder = RedactionPolicy::builder();
    builder
        .edit_fields()
        .raise("password", Sensitivity::Secret)
        .expect("the key rule should be valid");
    builder.limits().domain(
        DomainRedactionLimits::builder()
            .max_nodes(8)
            .max_collection_items(8)
            .max_depth(1)
            .build()
            .expect("the domain limits should be valid"),
    );
    let policy = builder.build().expect("the policy should be valid");

    let output = format!("{:?}", NestedStandaloneKeyed.redacted_with(&policy));

    assert_eq!(output, "<truncated>");
}

/// Nested adapters must still charge exact input inside a domain output frame.
#[cfg(feature = "json")]
#[test]
fn test_domain_output_frame_does_not_precharge_nested_adapter_input() {
    let remaining = Cell::new(None);
    let json = r#"{"name":"visible"}"#;
    let value = NestedAdapterObserver {
        remaining: &remaining,
        json,
    };
    let policy = policy_with_limits(8, 8, 8, 64);

    let output = format!("{:?}", value.redacted_with(&policy));

    assert!(!output.is_empty());
    assert_eq!(remaining.get(), Some((64, 64 - json.len(), 64 - json.len())),);
}

/// Over-limit JSON is rejected before its visible source reaches parsing.
#[cfg(feature = "json")]
#[test]
fn test_domain_output_frame_rejects_nested_json_before_parsing() {
    let remaining = Cell::new(None);
    let value = NestedAdapterObserver {
        remaining: &remaining,
        json: r#"{"display":"visible"}"#,
    };
    let policy = policy_with_limits(8, 8, 8, 4);

    let output = format!("{:?}", value.redacted_with(&policy));

    assert_eq!(output, "<redacted>|NAME=visible");
    assert_eq!(remaining.get(), Some((4, 4, 4)));
}
