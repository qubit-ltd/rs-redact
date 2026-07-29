// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for bounded materialized masks during redacted formatting.

use std::collections::BTreeMap;

use qubit_redact::{LogOutputLimit, RedactedMap, RedactionPolicy};

/// Verifies bounded rendering keeps sensitive map values hidden and bounded.
#[test]
fn test_mask_byte_limit_keeps_sensitive_map_output_bounded() {
    let values = BTreeMap::from([("password", "secret-value".repeat(128))]);
    let limit = LogOutputLimit::new(24).expect("the bounded rendering limit should be valid");

    let output = RedactedMap::new(&values, RedactionPolicy::default())
        .with_output_limit(limit)
        .to_string();

    assert!(output.len() <= 24, "{output}");
    assert!(output.ends_with("<truncated>"), "{output}");
    assert!(!output.contains("secret-value"), "{output}");
}
