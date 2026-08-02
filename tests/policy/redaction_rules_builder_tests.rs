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

/// Verifies the application facade reports validation errors immediately from
/// the rules construction context.
#[test]
fn test_rules_builder_reports_rules_location_for_invalid_field_immediately() {
    assert_eq!(
        RedactionPolicy::builder()
            .raise(" -_[] ", Sensitivity::High)
            .expect_err("an empty canonical field name must fail immediately"),
        PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules,
        },
    );
}
