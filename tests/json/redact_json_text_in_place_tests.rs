// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for explicit JSON text transformation.

use qubit_redact::{
    DiagnosticBudget,
    RedactionPolicy,
    Sensitivity,
    redact_json_text_in_place,
};

/// Verifies explicit mutation preserves complete JSON beyond diagnostic limits.
#[test]
fn test_redact_json_text_in_place_is_not_limited_by_diagnostic_budget() {
    let policy = RedactionPolicy::builder()
        .diagnostic_budget(
            DiagnosticBudget::new(16, 64)
                .expect("the diagnostic budget should be valid"),
        )
        .raise("password", Sensitivity::Secret)
        .build()
        .expect("the policy should build");
    let mut text =
        format!(r#"{{"name":"{}","password":"raw"}}"#, "a".repeat(128));

    redact_json_text_in_place(&mut text, &policy);

    let value = serde_json::from_str::<serde_json::Value>(&text)
        .expect("the transformed text should remain valid JSON");
    assert_eq!(value["name"], "a".repeat(128));
    assert_ne!(value["password"], "raw");
    assert!(text.len() > policy.diagnostic_budget().max_input_bytes());
}
