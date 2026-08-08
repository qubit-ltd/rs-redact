// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public crate name.

use qubit_redact as redact;
/// Verifies that public exports are available through `qubit_redact`.
#[test]
fn test_crate_is_named_qubit_redact() {
    let _ = core::any::type_name::<redact::Redactor>();
}
