// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal redaction-policy contracts unavailable through the public API.

use crate::policy::FieldMatchKind;
use crate::policy::FieldNameMatching;
use crate::policy::MaskPolicy;
use crate::policy::RedactionFloor;
use crate::policy::RedactionPolicy;
use crate::policy::ResolvedField;
use crate::policy::SensitiveFieldPreset;
use crate::policy::Sensitivity;
use crate::policy::UnknownFieldPolicy;

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

/// Adding a floor preserves each layer's matching and unknown-field behavior.
#[test]
fn test_add_floor_preserves_matching_and_unknown_fallback() {
    let application_floor = RedactionFloor::builder()
        .matching(FieldNameMatching::Exact)
        .raise("qz_floor_marker", Sensitivity::High)
        .expect("application floor rule should be valid")
        .build()
        .expect("application floor should be valid");
    let policy = RedactionPolicy::standard()
        .with_floor(application_floor)
        .add_floor(RedactionFloor::standard());

    assert_eq!(policy.sensitivity_for("qz_floor_marker"), Some(Sensitivity::High));
    assert_eq!(policy.sensitivity_for("service_qz_floor_marker"), None);
    assert_eq!(policy.sensitivity_for("service_password"), Some(Sensitivity::Secret));

    let fallback_floor = RedactionFloor::builder()
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Medium))
        .build()
        .expect("fallback floor should be valid");
    let fallback_policy = RedactionPolicy::standard()
        .with_floor(fallback_floor)
        .add_floor(RedactionFloor::standard());
    assert_eq!(
        fallback_policy.sensitivity_for("unclassified_qz_field"),
        Some(Sensitivity::Medium)
    );
}

/// Runs the public policy inspection and field-builder API from the library's
/// unit-test target so coverage includes the library's own generic instances.
#[test]
fn test_policy_inspection_and_field_builder_snapshot() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .floor(RedactionFloor::standard())
                .disable_floor()
                .include_preset(SensitiveFieldPreset::Credentials)
                .matching(FieldNameMatching::ExactOrTokenSuffix)
                .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Low))
                .low_sensitive("notice")
                .medium_sensitive("session")
                .high_sensitive("trace_id")
                .raise("token", Sensitivity::High)
                .override_level("token", Sensitivity::Secret)
                .allow_exact("request_id")
                .remove_allow_exact("request_id")
                .allow_suffix("diagnostic")
                .remove_allow_suffix("diagnostic")
                .clear_allow_rules()
                .allow_suffix("diagnostic")
                .mask(Sensitivity::Medium, MaskPolicy::fixed("[medium]"));
        })
        .expect("field draft should be valid")
        .build()
        .expect("policy should be valid");

    assert!(policy.floor().is_none());
    assert_eq!(policy.matching(), FieldNameMatching::ExactOrTokenSuffix);
    assert_eq!(
        policy.unknown_field_policy(),
        UnknownFieldPolicy::Redact(Sensitivity::Low)
    );
    assert_eq!(policy.sensitivity_for("password"), Some(Sensitivity::Secret));
    assert_eq!(policy.sensitivity_for("notice"), Some(Sensitivity::Low));
    assert_eq!(policy.sensitivity_for("session"), Some(Sensitivity::Medium));
    assert_eq!(policy.sensitivity_for("trace_id"), Some(Sensitivity::High));
    assert_eq!(policy.sensitivity_for("token"), Some(Sensitivity::Secret));
    assert_eq!(policy.sensitivity_for("request_diagnostic"), None);
    let sensitive = policy.classify_field("password");
    assert_eq!(sensitive.sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(sensitive.matched_field(), Some("password"));
    assert_eq!(sensitive.match_kind(), Some(FieldMatchKind::Exact));
    assert!(!sensitive.is_allowed());
    assert!(!sensitive.is_unknown());
    let allowed = policy.classify_field("request_diagnostic");
    assert!(allowed.is_allowed());
    assert_eq!(allowed.match_kind(), Some(FieldMatchKind::TokenSuffix));
    assert_eq!(allowed.matched_field(), Some("diagnostic"));
    assert!(policy.classify_field("unclassified").is_unknown());
    assert!(policy.application_sensitive_rules().next().is_some());
    assert_eq!(policy.application_allow_rules().count(), 1);
    assert_eq!(policy.masking().mask_opaque(Sensitivity::Medium), "[medium]");

    let copied = policy.to_builder().build().expect("snapshot should copy");
    assert_eq!(copied.sensitivity_for("token"), Some(Sensitivity::Secret));
    let mut mutable = copied;
    assert!(mutable.set_disabled(true).is_disabled());
    assert!(!mutable.set_disabled(false).is_disabled());
    assert!(!RedactionPolicy::strict().is_disabled());
    assert_eq!(
        RedactionPolicy::default().matching(),
        FieldNameMatching::ExactOrTokenSuffix
    );
    assert!(policy.clone().disable_floor().floor().is_none());
}
