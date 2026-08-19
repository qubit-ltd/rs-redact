// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactMapValue`](qubit_redact::domain::RedactMapValue).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Debug;

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::domain::Redact;
use qubit_redact::domain::RedactValue;
use qubit_redact::domain::RedactionWriter;

struct MapDomain<'a, K, V>(&'a BTreeMap<K, V>);

impl<K, V> Redact for MapDomain<'_, K, V>
where
    K: AsRef<str> + Debug + Ord,
    V: RedactValue + Debug,
    for<'a> &'a BTreeMap<K, V>: IntoIterator<Item = (&'a K, &'a V), IntoIter: ExactSizeIterator>,
{
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("MapDomain", |fields| {
            fields.map("values", self.0);
        });
    }
}
/// Verifies map formatting classifies values using their runtime keys.
#[test]
fn test_redact_map_value_masks_sensitive_map_entry() {
    let map = BTreeMap::from([(String::from("password"), String::from("raw"))]);
    let rendered = Redactor::standard().redact(&MapDomain(&map)).into_text().into_string();

    assert!(!rendered.contains("raw"));
    assert!(rendered.contains("<redacted>"));
}

/// Verifies borrowed keys and cow values retain their map representation.
#[test]
fn test_redact_map_value_supports_borrowed_keys_and_cow_values() {
    let map = BTreeMap::from([
        ("label", Cow::Borrowed("visible")),
        ("password", Cow::Owned(String::from("raw"))),
    ]);

    let rendered = Redactor::standard().redact(&MapDomain(&map)).into_text().into_string();

    assert_eq!(
        rendered,
        r#"MapDomain { values: {"label": "visible", "password": "<redacted>"} }"#,
    );
}

/// Empty maps still complete their structured frame without attempting a
/// phantom collection admission at end-of-input.
#[test]
fn test_redact_map_value_renders_empty_map_without_truncation() {
    let map: BTreeMap<String, String> = BTreeMap::new();

    let output = Redactor::standard().redact(&MapDomain(&map));

    assert_eq!(output.text().as_str(), "MapDomain { values: {} }");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// Map traversal closes without reading the second entry once the shared
/// collection allowance is exhausted.
#[test]
fn test_redact_map_value_marks_collection_limit_after_admitted_entries() {
    let map = BTreeMap::from([
        (String::from("first"), String::from("visible")),
        (String::from("second"), String::from("must-not-render")),
    ]);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");

    let output = Redactor::new(policy).redact(&MapDomain(&map));

    assert!(output.text().as_str().contains("first"));
    assert!(!output.text().as_str().contains("must-not-render"));
    assert!(output.text().as_str().contains("<truncated>"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
}
