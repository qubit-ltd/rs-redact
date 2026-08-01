// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactionFloorState`](qubit_redact::RedactionFloorState).

use qubit_redact::{RedactionFloor, RedactionFloorState, RedactionPolicy, Sensitivity};

/// Verifies immutable transitions record the origin of the active floor.
#[test]
fn test_redaction_floor_state_tracks_global_explicit_and_disabled() {
    let inherited = RedactionPolicy::builder()
        .build()
        .expect("the inherited policy should be valid");
    let floor = RedactionFloor::builder()
        .raise("tenant_floor_secret", Sensitivity::Secret)
        .build()
        .expect("the explicit floor should be valid");

    let explicit = inherited.clone().with_floor(floor);
    let disabled = explicit.clone().disable_floor();

    assert_eq!(inherited.floor_state(), RedactionFloorState::Explicit);
    assert_eq!(explicit.floor_state(), RedactionFloorState::Explicit);
    assert_eq!(disabled.floor_state(), RedactionFloorState::Disabled);
}
