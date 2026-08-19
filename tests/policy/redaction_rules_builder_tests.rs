// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the shared application-rule construction kernel.

use qubit_redact::PolicyError;
use qubit_redact::PolicyLocation;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
/// Verifies the application facade reports validation errors immediately from
/// the rules construction context.
#[test]
fn test_rules_builder_reports_rules_location_for_invalid_field_immediately() {
    assert_eq!(
        RedactionPolicy::builder()
            .fields(|fields| {
                fields.sensitive(Sensitivity::High, " -_[] ");
            })
            .err(),
        Some(PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules,
        }),
    );
}
