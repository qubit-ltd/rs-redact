// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Floor sensitivity integration tests for JSON redaction.

#![cfg(feature = "json")]

use qubit_redact::MaskPolicy;
use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::formats::json::redact_json_text_in_place;

#[test]
fn test_json_uses_policy_mask_for_floor_matched_key() {
    let floor = RedactionFloor::builder()
        .raise("credential", Sensitivity::Low)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        let _ = builder.fields().floor(floor);
        builder
            .fields()
            .raise("credential", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[application]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the policy should build");
    let mut value = r#"{"credential":"value"}"#.to_owned();

    redact_json_text_in_place(&mut value, &policy);

    assert_eq!(value, r#"{"credential":"[application]"}"#);
}
