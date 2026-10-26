// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed output from already-admitted JSON with base and context rules.

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
    let value = json!({"password": {"nested": "raw-secret"}});
    let original = value.clone();
    let state = JsonRedactionState::new(
        policy.rules(),
        policy.rules(),
        policy.masking(),
        JsonUnkeyedValuePolicy::PassThrough,
        true,
    );

    let redacted = state.redact(&value);
    let text = serde_json::to_string(&redacted).expect("borrowed output should serialize");
    let outcome = state.outcome();

    assert_eq!(
        outcome,
        JsonRedactionOutcome::Complete { passed_unkeyed: false },
        "keyed redaction should complete without passing through unkeyed values",
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).expect("output should be JSON")["password"],
        policy.masking().mask_opaque(Sensitivity::Secret),
        "a sensitive non-string value should not remain unchanged",
    );
    assert!(
        text.contains(&format!(
            "\"password\":\"{}\"",
            policy.masking().mask_opaque(Sensitivity::Secret)
        )),
        "a sensitive non-string value should be replaced by a string mask",
    );
    assert_eq!(value, original, "borrowed output must leave the source unchanged");
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
    let value = json!({"credential": "raw-secret"});
    let original = value.clone();
    let state = JsonRedactionState::new(
        base.rules(),
        context.rules(),
        base.masking(),
        JsonUnkeyedValuePolicy::PassThrough,
        true,
    );

    let redacted = state.redact(&value);
    let text = serde_json::to_string(&redacted).expect("borrowed output should serialize");
    let outcome = state.outcome();

    assert_eq!(
        outcome,
        JsonRedactionOutcome::Complete { passed_unkeyed: false },
        "keyed redaction should complete without passing through unkeyed values",
    );
    assert!(
        !text.contains("raw-secret"),
        "context rules should not expose a value protected by base rules",
    );
    assert!(
        !text.contains("\"credential\":\"raw-secret\""),
        "the base sensitive rule should replace the credential with a string mask",
    );
    assert_eq!(value, original, "borrowed output must leave the source unchanged");
}
