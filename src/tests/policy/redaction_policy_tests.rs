// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal redaction-policy contracts unavailable through the public API.

use crate::policy::FieldNameMatching;
use crate::policy::RedactionFloor;
use crate::policy::RedactionPolicy;
use crate::policy::ResolvedField;
use crate::policy::Sensitivity;

/// Exact resolution applies application rules and the configured floor.
#[test]
fn test_resolve_field_exact_includes_application_and_floor_rules() {
    let base = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("api_token").allow_exact("request_id");
        })
        .expect("application rules should be valid")
        .build()
        .expect("policy should be valid");
    let floor = RedactionFloor::builder()
        .raise("mandatory_field", Sensitivity::High)
        .expect("floor rule should be valid")
        .build()
        .expect("floor should be valid");
    let policy = base.with_floor(floor);

    assert!(matches!(
        policy.resolve_field_exact("api_token"),
        ResolvedField::Sensitive {
            sensitivity: Sensitivity::Secret
        }
    ));
    assert!(matches!(
        policy.resolve_field_exact("mandatory_field"),
        ResolvedField::Sensitive {
            sensitivity: Sensitivity::High
        }
    ));
}

/// Exact resolution applies exact matching independently within each floor
/// layer.
#[test]
fn test_resolve_field_exact_keeps_floor_matching_independent() {
    let exact = RedactionFloor::builder()
        .matching(FieldNameMatching::Exact)
        .raise("token", Sensitivity::Secret)
        .expect("exact floor rule should be valid")
        .build()
        .expect("exact floor should be valid");
    let suffix = RedactionFloor::builder()
        .raise("pin", Sensitivity::Low)
        .expect("suffix floor rule should be valid")
        .build()
        .expect("suffix floor should be valid");
    let policy = RedactionPolicy::disabled().with_floor(exact).add_floor(suffix);

    assert_eq!(policy.sensitivity_for_exact("token"), Some(Sensitivity::Secret));
    assert_eq!(policy.sensitivity_for_exact("service_token"), None);
    assert_eq!(policy.sensitivity_for_exact("service_pin"), None);
    assert_eq!(policy.sensitivity_for("service_pin"), Some(Sensitivity::Low));
}
