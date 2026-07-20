// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`SensitivityLevel`](qubit_redact::SensitivityLevel).

use qubit_redact::SensitivityLevel;

#[test]
fn test_sensitivity_levels_have_increasing_strength() {
    assert!(SensitivityLevel::Low < SensitivityLevel::Medium);
    assert!(SensitivityLevel::Medium < SensitivityLevel::High);
    assert!(SensitivityLevel::High < SensitivityLevel::Secret);
}
