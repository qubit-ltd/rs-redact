// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public redaction policy accessors.

use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::UnknownFieldPolicy;

/// Policy inspection and snapshots preserve application and floor behavior.
#[test]
fn test_policy_public_accessors_and_floor_snapshot() {
    let base = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("api_token").allow_exact("request_id");
        })
        .expect("application rules should be valid")
        .build()
        .expect("policy should be valid");
    let floor = RedactionFloor::builder()
        .raise("mandatory_field", Sensitivity::High)
        .expect("floor rule should be valid")
        .build()
        .expect("floor should be valid");
    let policy = base.with_floor(floor.clone());

    assert!(policy.floor().is_some());
    assert_eq!(policy.unknown_field_policy(), UnknownFieldPolicy::PassThrough);
    assert_eq!(
        policy
            .application_sensitive_rules()
            .map(|rule| (rule.field(), rule.sensitivity()))
            .collect::<Vec<_>>(),
        [("apitoken", Sensitivity::Secret)]
    );
    assert_eq!(
        policy
            .application_allow_rules()
            .map(|rule| rule.field())
            .collect::<Vec<_>>(),
        ["requestid"]
    );
    let classification = policy.classify_field("api_token");
    assert_eq!(classification.sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(classification.matched_field(), Some("apitoken"));
    assert_eq!(policy.sensitivity_for("mandatory_field"), Some(Sensitivity::High));

    let copied = policy.to_builder().build().expect("snapshot should remain valid");
    assert_eq!(copied.floor().map(|floor| floor.sensitive_rules().count()), Some(1));
    assert_eq!(copied.sensitivity_for("api_token"), Some(Sensitivity::Secret));
    assert!(policy.clone().disable_floor().floor().is_none());
    assert_eq!(
        RedactionPolicy::default().sensitivity_for("password"),
        Some(Sensitivity::Secret)
    );

    let mut mutable = copied;
    assert!(mutable.set_disabled(true).is_disabled());
    assert!(!mutable.set_disabled(false).is_disabled());
}
