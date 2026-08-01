// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Floor masking integration tests for JSON redaction.

use qubit_redact::{
    MaskPolicy, RedactionFloor, RedactionPolicy, Sensitivity, redact_json_text_in_place,
};

#[test]
fn test_json_uses_floor_mask_for_floor_matched_key() {
    let floor = RedactionFloor::empty_builder()
        .raise("credential", Sensitivity::Low)
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[floor]"))
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::empty_builder()
        .floor(floor)
        .raise("credential", Sensitivity::Secret)
        .build()
        .expect("the policy should build");
    let mut value = r#"{"credential":"value"}"#.to_owned();

    redact_json_text_in_place(&mut value, &policy);

    assert_eq!(value, r#"{"credential":"[floor]"}"#);
}
