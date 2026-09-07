// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public JSON text adapter enforces decoder admission before building a tree.

use qubit_redact::RedactionPolicy;
use qubit_redact::domain::internal::RedactedJsonSerializeRef;
use serde_json::to_value;

/// Verifies JSON-text fields are rejected by the decoder before an
/// over-limit tree can be materialized.
#[test]
fn test_json_text_serde_adapter_enforces_json_decode_limits() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_json_nodes(1);
        })
        .expect("limits")
        .build()
        .expect("redaction policy");
    let source = r#"{"outer":{"token":"raw-secret"}}"#;

    let encoded = to_value(RedactedJsonSerializeRef::new(source, &policy)).expect("JSON-text adapter serialization");

    assert_eq!(encoded, "<redacted>");
}
