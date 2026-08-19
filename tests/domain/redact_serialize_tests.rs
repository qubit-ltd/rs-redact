// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for serde redaction hooks on domain objects.

#[cfg(feature = "serde")]
use qubit_redact::RedactionPolicy;
#[cfg(feature = "serde")]
use qubit_redact::domain::RedactSerialize;

#[cfg(feature = "serde")]
struct SerializableDomain;

#[cfg(feature = "serde")]
impl RedactSerialize for SerializableDomain {
    fn serialize_redacted<S>(&self, _policy: &RedactionPolicy, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("safe")
    }
}

/// Verifies a domain serialization hook writes a redacted representation.
#[cfg(feature = "serde")]
#[test]
fn test_redact_serialize_writes_redacted_representation() {
    let rendered = SerializableDomain
        .serialize_redacted(&RedactionPolicy::standard(), serde_json::value::Serializer)
        .expect("redacted serialization should succeed");

    assert_eq!(rendered, serde_json::json!("safe"));
}
