// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Already-admitted JSON mutation with base and HTTP context rules.

use serde_json::json;

use crate::RedactionPolicy;
use crate::Sensitivity;
use crate::formats::json::internal::JsonRedactionOutcome;
use crate::formats::json::internal::JsonRedactionState;
use crate::formats::json::internal::JsonUnkeyedValuePolicy;

#[test]
fn test_sensitive_non_string_value_is_replaced_by_an_opaque_mask() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.sensitive(Sensitivity::Secret, "password");
        })
        .expect("test rules should build")
        .build()
        .expect("test policy should build");
    let mut value = json!({"password": {"nested": "raw-secret"}});
    let mut state = JsonRedactionState::new(
        policy.rules(),
        policy.rules(),
        policy.masking(),
        JsonUnkeyedValuePolicy::PassThrough,
    );

    let outcome = state.redact(&mut value);

    assert!(matches!(outcome, JsonRedactionOutcome::Complete { .. }));
    assert_ne!(value["password"], json!({"nested": "raw-secret"}));
    assert!(value["password"].is_string());
}

#[test]
fn test_context_rules_do_not_weaken_a_base_sensitive_rule() {
    let base = RedactionPolicy::builder()
        .fields(|fields| {
            fields.sensitive(Sensitivity::Secret, "credential");
        })
        .expect("base rules should build")
        .build()
        .expect("base policy should build");
    let context = RedactionPolicy::standard();
    let mut value = json!({"credential": "raw-secret"});
    let mut state = JsonRedactionState::new(
        base.rules(),
        context.rules(),
        base.masking(),
        JsonUnkeyedValuePolicy::PassThrough,
    );

    let outcome = state.redact(&mut value);

    assert!(matches!(outcome, JsonRedactionOutcome::Complete { .. }));
    assert!(!value.to_string().contains("raw-secret"));
    assert!(value["credential"].is_string());
}
