// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! External tests for minimum redaction floors.

use proptest::prop_assert;
use proptest::prop_assert_eq;
use proptest::proptest;
use qubit_redact::FieldNameMatching;
use qubit_redact::MaskPolicy;
use qubit_redact::PolicyError;
use qubit_redact::PolicyLocation;
use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::UnknownFieldPolicy;

#[test]
fn test_added_floor_preserves_unknown_secret() {
    let first = RedactionFloor::builder()
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Secret))
        .build()
        .expect("valid first floor");
    let second = RedactionFloor::builder()
        .raise("pin", Sensitivity::Low)
        .expect("valid rule")
        .build()
        .expect("valid second floor");
    let policy = RedactionPolicy::standard().with_floor(first).add_floor(second);
    assert_eq!(policy.sensitivity_for("pin"), Some(Sensitivity::Secret));
}

#[test]
fn test_added_floor_preserves_each_layer_fallback_and_matching() {
    let same_layer = RedactionFloor::builder()
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Secret))
        .raise("pin", Sensitivity::Low)
        .expect("valid rule")
        .build()
        .expect("valid same-layer floor");
    let policy = RedactionPolicy::standard().with_floor(same_layer);
    assert_eq!(policy.sensitivity_for("pin"), Some(Sensitivity::Low));

    let exact = RedactionFloor::builder()
        .matching(FieldNameMatching::Exact)
        .raise("token", Sensitivity::Secret)
        .expect("valid exact rule")
        .build()
        .expect("valid exact floor");
    let suffix = RedactionFloor::builder()
        .raise("pin", Sensitivity::Low)
        .expect("valid suffix rule")
        .build()
        .expect("valid suffix floor");
    let policy = RedactionPolicy::disabled()
        .with_floor(exact.clone())
        .add_floor(suffix.clone());
    assert_eq!(policy.sensitivity_for("token"), Some(Sensitivity::Secret));
    assert_eq!(policy.sensitivity_for("service_token"), None);
    // The exact layer does not create or alter a suffix rule.
    assert_eq!(policy.sensitivity_for("pin"), Some(Sensitivity::Low));
    assert_eq!(policy.sensitivity_for("service_pin"), Some(Sensitivity::Low));

    let reversed = RedactionPolicy::disabled().with_floor(suffix).add_floor(exact);
    for field in ["token", "service_token", "pin", "service_pin"] {
        assert_eq!(policy.sensitivity_for(field), reversed.sensitivity_for(field));
    }
}

#[test]
fn test_added_floor_is_associative_idempotent_and_builder_round_trips() {
    let first = RedactionFloor::builder()
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::High))
        .build()
        .expect("valid first floor");
    let second = RedactionFloor::builder()
        .raise("pin", Sensitivity::Low)
        .expect("valid second rule")
        .build()
        .expect("valid second floor");
    let third = RedactionFloor::builder()
        .matching(FieldNameMatching::Exact)
        .raise("credential", Sensitivity::Secret)
        .expect("valid third rule")
        .build()
        .expect("valid third floor");
    let left = RedactionPolicy::disabled()
        .with_floor(first.clone())
        .add_floor(second.clone())
        .add_floor(third.clone());
    let right = RedactionPolicy::disabled()
        .with_floor(third)
        .add_floor(second)
        .add_floor(first);
    for field in ["pin", "credential", "service_credential", "unconfigured"] {
        let expected = left.sensitivity_for(field);
        assert_eq!(right.sensitivity_for(field), expected);
    }
    let standard = RedactionPolicy::standard();
    let standard_plus_once = standard.clone().add_floor(RedactionFloor::standard());
    let standard_plus_twice = standard_plus_once.clone().add_floor(RedactionFloor::standard());
    for field in ["password", "token", "unconfigured"] {
        assert_eq!(
            standard_plus_once.sensitivity_for(field),
            standard.sensitivity_for(field)
        );
        assert_eq!(
            standard_plus_twice.sensitivity_for(field),
            standard.sensitivity_for(field)
        );
    }
    let copied = left
        .rules()
        .floor()
        .expect("floor present")
        .to_builder()
        .build()
        .expect("composed floor round trip");
    let round_trip = RedactionPolicy::disabled().with_floor(copied);
    for field in ["pin", "credential", "service_credential", "unconfigured"] {
        assert_eq!(round_trip.sensitivity_for(field), left.sensitivity_for(field));
    }
    let replacement = RedactionFloor::builder()
        .raise("replacement", Sensitivity::Medium)
        .expect("valid replacement")
        .build()
        .expect("valid replacement floor");
    let replaced = left.rules().clone().disable_floor().with_floor(replacement);
    assert_eq!(replaced.sensitivity_for("pin"), None);
    assert_eq!(replaced.sensitivity_for("replacement"), Some(Sensitivity::Medium));
}

#[test]
fn test_floor_overrides_application_exact_allow() {
    let floor = RedactionFloor::builder()
        .raise("access_token", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.floor(floor).allow_exact("access_token");
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should build");
    assert_eq!(policy.sensitivity_for("access_token"), Some(Sensitivity::High));
}

/// Verifies that a suffix allow cannot bypass a matching floor rule.
#[test]
fn test_floor_overrides_application_suffix_allow() {
    let floor = RedactionFloor::builder()
        .raise("access_token", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.floor(floor).allow_suffix("access_token");
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should build");

    assert_eq!(policy.sensitivity_for("service_access_token"), Some(Sensitivity::High),);
}

#[test]
fn test_floor_only_raises_sensitivity_when_application_level_is_higher() {
    let floor = RedactionFloor::builder()
        .raise("credential", Sensitivity::Low)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .floor(floor)
                .raise("credential", Sensitivity::Secret)
                .mask(Sensitivity::Secret, MaskPolicy::fixed("[application]"));
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should build");
    assert_eq!(policy.sensitivity_for("credential"), Some(Sensitivity::Secret),);
    assert_eq!(
        Redactor::new(policy)
            .redact_field("credential", "value")
            .text()
            .as_str(),
        "[application]"
    );
}

/// Verifies that each layer's unknown-field fallback participates in the final
/// maximum while the shared application mask renders the result.
#[test]
fn test_floor_and_application_unknown_fallbacks_combine() {
    let floor = RedactionFloor::builder()
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Medium))
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .floor(floor)
                .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Secret))
                .mask(Sensitivity::Secret, MaskPolicy::fixed("[application-secret]"));
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should build");

    assert_eq!(
        policy.sensitivity_for("unconfigured_reference"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        Redactor::new(policy)
            .redact_field("unconfigured_reference", "value")
            .text()
            .as_str(),
        "[application-secret]",
    );
}

/// Verifies application masking remains authoritative when the floor does not
/// classify a field.
#[test]
fn test_application_mask_is_used_when_floor_misses() {
    let floor = RedactionFloor::builder()
        .raise("floor_only", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .floor(floor)
                .raise("application_only", Sensitivity::Secret)
                .mask(Sensitivity::Secret, MaskPolicy::fixed("[application]"));
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should build");

    assert_eq!(
        Redactor::new(policy)
            .redact_field("application_only", "value")
            .text()
            .as_str(),
        "[application]",
    );
}

#[test]
fn test_floor_matching_is_independent_from_application_matching() {
    let floor = RedactionFloor::builder()
        .matching(FieldNameMatching::Exact)
        .raise("token", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.floor(floor).matching(FieldNameMatching::ExactOrTokenSuffix);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should build");

    assert_eq!(policy.sensitivity_for("service_token"), None);
}

#[test]
fn test_disable_floor_is_last_call_wins() {
    let floor = RedactionFloor::builder()
        .raise("credential", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.floor(floor).disable_floor();
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should build");
    assert_eq!(policy.sensitivity_for("credential"), None);
}

/// Verifies replacing a disabled floor restores explicit protection.
#[test]
fn test_with_floor_after_disable_floor_is_last_call_wins() {
    let floor = RedactionFloor::builder()
        .raise("credential", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor().floor(floor);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should build");

    assert_eq!(policy.sensitivity_for("credential"), Some(Sensitivity::High),);
}

/// Verifies disabled floor snapshots are copied and default copying replaces
/// the complete floor configuration.
#[test]
fn test_builder_copy_and_standard_preserve_or_replace_floor_configuration() {
    let disabled = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor().raise("application_only", Sensitivity::High);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the disabled policy should build");
    let copied = disabled.to_builder().build().expect("the copied policy should build");
    let reset = RedactionPolicy::default()
        .to_builder()
        .build()
        .expect("the default-reset policy should build");

    assert_eq!(copied, disabled);
    assert_eq!(reset, RedactionPolicy::default());
}

/// Verifies public rule views keep application rules and floor rules separate.
#[test]
fn test_rule_views_keep_application_and_floor_sources_separate() {
    let floor = RedactionFloor::builder()
        .raise("floor_only", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .floor(floor)
                .raise("application_only", Sensitivity::Medium)
                .allow_exact("application_visible");
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy should build");

    assert_eq!(
        policy
            .application_sensitive_rules()
            .map(|rule| rule.field())
            .collect::<Vec<_>>(),
        vec!["applicationonly"],
    );
    assert_eq!(
        policy
            .application_allow_rules()
            .map(|rule| rule.field())
            .collect::<Vec<_>>(),
        vec!["applicationvisible"],
    );
    assert_eq!(
        policy
            .floor()
            .expect("the configured floor should be present")
            .sensitive_rules()
            .map(|rule| rule.field())
            .collect::<Vec<_>>(),
        vec!["flooronly"],
    );
}

#[test]
fn test_floor_validation_reports_floor_location() {
    let result = RedactionFloor::builder()
        .raise(" _-.[ ] ", Sensitivity::High)
        .expect_err("an empty floor field name must fail immediately");
    assert_eq!(
        result,
        PolicyError::EmptyFieldName {
            location: PolicyLocation::Floor
        }
    );
}

/// Verifies floor defaults, snapshot builders, and display all preserve the
/// active global floor contract.
#[test]
fn test_floor_default_builder_snapshot_and_display_are_consistent() {
    let from_default = RedactionFloor::default()
        .to_builder()
        .build()
        .expect("the default-derived floor should build");
    let default_floor = RedactionFloor::default();

    assert_eq!(from_default, RedactionFloor::standard());
    assert_eq!(default_floor, RedactionFloor::standard());
    assert_eq!(RedactionFloor::standard().to_string(), "RedactionFloor");
}

/// Maps a generated index to one supported sensitivity level.
fn sensitivity_from_index(index: u8) -> Sensitivity {
    match index {
        0 => Sensitivity::Low,
        1 => Sensitivity::Medium,
        2 => Sensitivity::High,
        _ => Sensitivity::Secret,
    }
}

proptest! {
    /// Verifies an enabled floor can never be weakened by application rules.
    #[test]
    fn test_enabled_floor_effective_level_is_never_weaker(
        floor_index in 0_u8..4,
        application_index in 0_u8..4,
    ) {
        let floor_level = sensitivity_from_index(floor_index);
        let application_level = sensitivity_from_index(application_index);
        let floor = RedactionFloor::builder()
            .raise("shared_field", floor_level).expect("the test builder input should be valid")
            .build()
            .expect("the generated floor should build");
        let policy = RedactionPolicy::builder()
            .fields(|fields| {
                fields
                    .floor(floor)
                    .raise("shared_field", application_level);
            })
            .expect("the field configuration should be valid")
            .build()
            .expect("the generated policy should build");

        prop_assert!(
            policy
                .sensitivity_for("shared_field")
                .expect("the floor always classifies the generated field")
                >= floor_level,
        );
    }

    /// Verifies disabling a floor restores pure application-rule behavior.
    #[test]
    fn test_disabled_floor_matches_application_only(
        floor_index in 0_u8..4,
        application_index in 0_u8..4,
    ) {
        let floor = RedactionFloor::builder()
            .raise("shared_field", sensitivity_from_index(floor_index)).expect("the test builder input should be valid")
            .build()
            .expect("the generated floor should build");
        let disabled = RedactionPolicy::builder()
            .fields(|fields| {
                fields
                    .floor(floor)
                    .disable_floor()
                    .raise("shared_field", sensitivity_from_index(application_index));
            })
            .expect("the field configuration should be valid")
            .build()
            .expect("the disabled policy should build");
        let application_only = RedactionPolicy::builder()
            .fields(|fields| {
                fields
                    .disable_floor()
                    .raise("shared_field", sensitivity_from_index(application_index));
            })
            .expect("the field configuration should be valid")
            .build()
            .expect("the application-only policy should build");

        prop_assert_eq!(
            disabled.sensitivity_for("shared_field"),
            application_only.sensitivity_for("shared_field"),
        );
    }
}
