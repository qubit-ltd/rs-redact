// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Rendering runtime's unpublished mode contract.

use std::sync::Arc;

use crate::RedactionPolicy;
use crate::Sensitivity;
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// Rendering sessions expose their shared core and ignore inspection
/// observations.
#[test]
fn test_rendering_runtime_implements_its_typed_mode_contract() {
    let policy = Arc::new(RedactionPolicy::standard());
    let mut runtime = TextSession::new(policy);

    assert!(
        !RuntimeSession::is_inspection(&runtime),
        "rendering sessions must not use inspection mode"
    );
    RuntimeSession::observe_sensitivity(&mut runtime, Sensitivity::Secret);
    let shared_core = RuntimeSession::runtime(&runtime) as *const _;

    assert!(
        std::ptr::eq(shared_core, RuntimeSession::runtime_mut(&mut runtime)),
        "immutable and mutable accessors must expose the same runtime core"
    );
}
