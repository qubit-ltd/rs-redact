// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedMap`](qubit_redact::RedactedMap).

use std::collections::BTreeMap;

use indexmap::IndexMap;
use qubit_redact::{
    InputOutputLimit,
    RedactedMap,
    RedactionPolicy,
};

/// Verifies a redacted map keeps non-sensitive values visible.
#[test]
fn test_redacted_map_preserves_visible_value() {
    let map =
        BTreeMap::from([(String::from("label"), String::from("visible"))]);
    let rendered =
        RedactedMap::new(&map, RedactionPolicy::default()).to_string();

    assert!(rendered.contains("visible"));
}

/// Verifies generic map support preserves IndexMap insertion order.
#[test]
fn test_redacted_map_supports_index_map_without_runtime_coupling() {
    let map = IndexMap::from([("password", "raw"), ("label", "visible")]);

    let rendered =
        format!("{:?}", RedactedMap::new(&map, RedactionPolicy::default()),);

    assert_eq!(
        rendered,
        r#"{"password": "<redacted>", "label": "visible"}"#,
    );
}

/// Verifies map display uses its policy output budget by default.
#[test]
fn test_redacted_map_display_uses_policy_output_limit_by_default() {
    let map = BTreeMap::from([(
        String::from("label"),
        "visible diagnostic text".repeat(4),
    )]);
    let budget =
        InputOutputLimit::new(1024, InputOutputLimit::MIN_OUTPUT_BYTES)
            .expect("the minimum bounded output should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the diagnostic budget should build a policy");

    let output = RedactedMap::new(&map, policy).to_string();

    assert!(output.len() <= budget.max_output_bytes());
    assert!(output.ends_with("<truncated>"));
}
