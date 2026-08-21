// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactMapValueMut`](qubit_redact::RedactMapValueMut).

use std::borrow::Cow;
use std::collections::BTreeMap;

use qubit_redact::RedactMapValueMut;
use qubit_redact::RedactionPolicy;
/// Verifies in-place map redaction replaces only sensitive values.
#[test]
fn test_redact_map_value_mut_replaces_sensitive_value() {
    let mut map = BTreeMap::from([(String::from("password"), String::from("raw"))]);
    map.redact_map_in_place(&RedactionPolicy::default());

    assert_eq!(map["password"], "<redacted>");
}

/// Verifies in-place redaction supports borrowed keys and owned cow masks.
#[test]
fn test_redact_map_value_mut_supports_borrowed_keys_and_cow_values() {
    let mut map = BTreeMap::from([("label", Cow::Borrowed("visible")), ("password", Cow::Borrowed("raw"))]);

    map.redact_map_in_place(&RedactionPolicy::default());

    assert_eq!(map["label"].as_ref(), "visible");
    assert_eq!(map["password"].as_ref(), "<redacted>");
    assert!(matches!(&map["password"], Cow::Owned(_)));
}
