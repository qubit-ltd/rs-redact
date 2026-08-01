// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the shared application-rule construction kernel.

use qubit_redact::{
    PolicyError,
    PolicyLocation,
    RedactionPolicy,
    Sensitivity,
};

/// Verifies the application facade reports validation errors from the rules
/// construction context.
#[test]
fn test_rules_builder_reports_rules_location_for_invalid_field() {
    assert_eq!(
        RedactionPolicy::empty_builder()
            .raise(" -_[] ", Sensitivity::High)
            .build(),
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules,
        }),
    );
}
