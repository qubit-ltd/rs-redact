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
