// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`Sensitivity`](qubit_redact::Sensitivity).

use qubit_redact::Sensitivity;

/// Verifies sensitivity ordering increases with secrecy.
#[test]
fn test_sensitivity_orders_from_low_to_secret() {
    assert!(Sensitivity::Low < Sensitivity::Medium);
    assert!(Sensitivity::Medium < Sensitivity::High);
    assert!(Sensitivity::High < Sensitivity::Secret);
}
