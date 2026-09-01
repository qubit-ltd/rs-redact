// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Boundary coverage for domain writer modes and shared budgets.

#![cfg(feature = "json")]

use std::collections::BTreeMap;
use std::fmt;

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// Debug value that emits multiple fragments so bounded writers can stop it
/// before later fragments are evaluated.
struct FragmentedDebug;

impl fmt::Debug for FragmentedDebug {
    /// Emits two independently bounded fragments.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("first-fragment")?;
        formatter.write_str("raw-secret")
    }
}

/// Small nested value shared by all writer scopes.
struct NestedValue;

impl Redact for NestedValue {
    /// Writes a stable safe marker.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("nested-safe");
    }
}

/// Exercises every public domain-writer scope and field mode.
struct CompleteWriterSurface;

impl Redact for CompleteWriterSurface {
    /// Writes records, tuples, transparent fields, sequences, maps, variants,
    /// JSON, nested values, skipped fields, and trusted values.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        let sensitive_map = BTreeMap::from([
            (String::from("password"), String::from("raw-map-secret")),
            (String::from("public"), String::from("visible")),
        ]);
        let explicit_map = BTreeMap::from([(String::from("raw-key-secret"), String::from("raw-value-secret"))]);
        let json = serde_json::json!({"password": "raw-json-secret", "public": "visible"});

        writer.unredacted(&"trusted").unmarked(&"trusted-alias");
        writer.record("Surface", |fields| {
            fields
                .unredacted("public", || "visible")
                .sensitive(Sensitivity::Low, "low", || FragmentedDebug)
                .sensitive(Sensitivity::Secret, "secret", || "must-not-run")
                .sensitive_value(Sensitivity::Medium, "medium", &String::from("raw-medium"))
                .json("json_text", r#"{"password":"raw-json-text-secret"}"#)
                .json_value("json_value", &json)
                .nested("nested", &NestedValue)
                .map_value("classified_map", &sensitive_map)
                .map_level_values(
                    "explicit_map",
                    &explicit_map,
                    Sensitivity::Secret,
                    Some(Sensitivity::Secret),
                )
                .keyed_value("keyed", "password", &String::from("raw-keyed-secret"))
                .skipped("skipped", || "raw-skipped-secret");
        });
        writer.tuple("Tuple", |fields| {
            fields.unredacted("", || "visible").nested("", &NestedValue);
        });
        writer.transparent(|fields| {
            fields.unredacted("", || "transparent");
        });
        writer.sequence(|items| {
            items
                .unredacted_item(|| "visible")
                .sensitive_item(Sensitivity::Low, || FragmentedDebug)
                .sensitive_item(Sensitivity::Secret, || "must-not-run")
                .json_value_item(&json)
                .nested_item(&NestedValue);
        });
        writer.map(|entries| {
            entries
                .unredacted_entry("public", || "visible")
                .sensitive_entry(Sensitivity::Low, "low", || FragmentedDebug)
                .sensitive_entry(Sensitivity::Secret, "secret", || "must-not-run")
                .nested_entry("nested", &NestedValue);
        });
        writer.variant("Example", "Variant", |fields| {
            fields.unredacted("public", || "visible");
        });
    }
}

/// Structure that begins exactly one requested domain scope.
enum SingleScope {
    Record,
    Sequence,
    Map,
}

impl Redact for SingleScope {
    /// Begins the selected scope so depth rejection paths are independently
    /// observable.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        match self {
            Self::Record => writer.record("Record", |fields| {
                fields.unredacted("value", || "visible");
            }),
            Self::Sequence => writer.sequence(|items| {
                items.unredacted_item(|| "visible");
            }),
            Self::Map => writer.map(|entries| {
                entries.unredacted_entry("value", || "visible");
            }),
        }
    }
}

/// Verifies render, inspection, and disabled modes traverse the same writer
/// surface without leaking enabled-mode sensitive inputs.
#[test]
fn test_domain_writer_surface_covers_render_inspection_and_disabled_modes() {
    let standard = Redactor::standard();
    let rendered = standard.redact(&CompleteWriterSurface);
    let inspected = standard
        .inspect(&CompleteWriterSurface)
        .expect("inspection should complete");
    let disabled = Redactor::new(RedactionPolicy::disabled()).redact(&CompleteWriterSurface);

    assert!(!rendered.text().as_str().contains("raw-"));
    assert_eq!(inspected.max_sensitivity(), Some(Sensitivity::Secret));
    assert!(disabled.text().as_str().contains("raw-map-secret"));
    assert!(disabled.text().as_str().contains("raw-skipped-secret"));
}

/// Verifies record, sequence, and map scope admission each fail closed when no
/// domain depth is available.
#[test]
fn test_domain_writer_scope_types_fail_closed_at_zero_depth() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(0);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);

    for value in [SingleScope::Record, SingleScope::Sequence, SingleScope::Map] {
        let output = redactor.redact(&value);
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(!output.text().as_str().contains("visible"));
    }
}

/// Verifies collection and output exhaustion stop later accessors and report a
/// truthful truncated result.
#[test]
fn test_domain_writer_stops_accessors_at_collection_and_output_limits() {
    let collection_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(0);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(8);
        })
        .expect("limits")
        .build()
        .expect("policy");

    let collection_output = Redactor::new(collection_policy).redact(&CompleteWriterSurface);
    let output_limited = Redactor::new(output_policy).redact(&CompleteWriterSurface);

    assert_eq!(collection_output.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(output_limited.summary().completion(), RedactionCompletion::Exhausted);
    assert!(output_limited.text().as_str().len() <= 8);
    assert!(!output_limited.text().as_str().contains("raw-secret"));
}

/// Verifies invalid and input-rejected JSON fields publish only safe bounded
/// diagnostics through the enclosing domain transaction.
#[test]
fn test_domain_json_fields_fail_closed_for_invalid_and_input_limited_values() {
    struct JsonFields;

    impl Redact for JsonFields {
        /// Writes invalid text and a parsed value through the domain writer.
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("JsonFields", |fields| {
                fields
                    .json("invalid", "{raw-secret")
                    .json_value("parsed", &serde_json::json!({"password": "raw-secret"}));
            });
        }
    }

    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(0);
            limits.max_json_nodes(0);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact(&JsonFields);

    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(!output.text().as_str().contains("raw-secret"));
}
