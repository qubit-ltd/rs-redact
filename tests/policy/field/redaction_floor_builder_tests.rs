// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactionFloorBuilder`](qubit_redact::RedactionFloorBuilder).

use qubit_redact::FieldNameMatching;
use qubit_redact::RedactionFloor;
use qubit_redact::Sensitivity;
use qubit_redact::UnknownFieldPolicy;

/// Verifies copying a floor preserves every builder-owned rule choice.
#[test]
fn test_redaction_floor_builder_from_copies_complete_floor() {
    let floor = RedactionFloor::builder()
        .matching(FieldNameMatching::Exact)
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Medium))
        .raise("tenant_secret", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the source floor should be valid");

    let copied = floor.to_builder().build().expect("the copied floor should be valid");

    assert_eq!(copied, floor);
}

#[test]
fn test_redaction_floor_builder_edits_first_composed_layer_and_retains_others() {
    let first = RedactionFloor::builder()
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::High))
        .build()
        .expect("valid first floor");
    let second = RedactionFloor::builder()
        .matching(FieldNameMatching::Exact)
        .raise("credential", Sensitivity::Secret)
        .expect("valid rule")
        .build()
        .expect("valid second floor");
    let policy = qubit_redact::RedactionPolicy::disabled()
        .with_floor(first)
        .add_floor(second);
    let composed = policy.rules().floor().expect("floor present");

    let edited = composed
        .to_builder()
        .matching(FieldNameMatching::Exact)
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Low))
        .raise("pin", Sensitivity::Medium)
        .expect("valid edit")
        .build()
        .expect("edited floor should build");
    let rebuilt = qubit_redact::RedactionPolicy::disabled().with_floor(edited);

    assert_eq!(rebuilt.sensitivity_for("unconfigured"), Some(Sensitivity::Low));
    assert_eq!(rebuilt.sensitivity_for("pin"), Some(Sensitivity::Medium));
    assert_eq!(rebuilt.sensitivity_for("credential"), Some(Sensitivity::Secret));
    assert_eq!(rebuilt.sensitivity_for("service_credential"), Some(Sensitivity::Low));
}
