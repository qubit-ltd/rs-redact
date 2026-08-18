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

use qubit_redact::RedactionPolicy;
use qubit_redact::domain::RedactedMap;
/// Verifies map formatting classifies values using their runtime keys.
#[test]
fn test_redact_map_value_masks_sensitive_map_entry() {
    let map = BTreeMap::from([(String::from("password"), String::from("raw"))]);
    let rendered = RedactedMap::new(&map, RedactionPolicy::default()).to_string();

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

    let rendered = format!("{:?}", RedactedMap::new(&map, RedactionPolicy::default()),);

    assert_eq!(rendered, r#"{"label": "visible", "password": "<redacted>"}"#,);
}
