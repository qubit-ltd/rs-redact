// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for JSON feature-gate macro expansion.

#![cfg(feature = "json")]

use qubit_budget::JsonValueBudget;
use qubit_budget::JsonValueLimits;
use qubit_redact::__qubit_redact_json;
__qubit_redact_json! {
    const JSON_FEATURE_GATE_MARKER: &str = "json";
}

/// Verifies the JSON feature gate preserves its wrapped items.
#[test]
fn test_json_feature_gate_expands_wrapped_items() {
    assert_eq!(JSON_FEATURE_GATE_MARKER, "json");
}

/// Verifies the JSON feature enables JSON-specific budget semantics upstream.
#[test]
fn test_json_feature_exposes_budget_json_semantics() {
    let _: JsonValueBudget = JsonValueBudget::new(JsonValueLimits::default());
}
