// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable redaction policies and rule matching.

use proptest::prop_assert_eq;
use proptest::proptest;
use qubit_redact::FieldNameMatching;
use qubit_redact::MaskPolicy;
use qubit_redact::PolicyError;
use qubit_redact::PolicyLocation;
#[cfg(feature = "http")]
use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionPolicyBuilder;
use qubit_redact::SensitiveFieldPreset;
use qubit_redact::Sensitivity;
#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
use qubit_redact::UnkeyedJsonValuePolicy;
use qubit_redact::UnknownFieldPolicy;
#[cfg(feature = "http")]
use qubit_redact::formats::http::TextBodyPolicy;
#[cfg(feature = "http")]
use qubit_redact::formats::http::UrlPathPolicy;
#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
use qubit_redact::formats::uri::UriFragmentPolicy;
#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
use qubit_redact::formats::uri::UriPathPolicy;

/// A policy must reject output limits that cannot be represented by Rust's
/// collection allocators instead of deferring failure to a renderer.
#[test]
fn limits_draft_rejects_unaddressable_output_capacity() {
    let result = RedactionPolicy::builder().limits(|limits| {
        limits.max_output_bytes(usize::MAX);
    });

    assert!(matches!(result, Err(PolicyError::OutputLimitTooLarge { .. })));
}

/// Verifies every field-builder validation path preserves transactional
/// failure instead of partially applying invalid names.
#[test]
fn test_fields_builder_rejects_invalid_names_for_every_rule_operation() {
    let results = [
        RedactionPolicy::builder().fields(|fields| {
            fields.low_sensitive("_");
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.medium_sensitive("_");
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.high_sensitive("_");
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.secret_sensitive("_");
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.sensitive(Sensitivity::Secret, "_");
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.raise("_", Sensitivity::High);
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.override_level("_", Sensitivity::High);
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.allow_exact("_");
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.allow_suffix("_");
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.remove_allow_exact("_");
        }),
        RedactionPolicy::builder().fields(|fields| {
            fields.remove_allow_suffix("_");
        }),
    ];

    assert!(results.into_iter().all(|result| matches!(
        result,
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules
        })
    )));
}

/// Exercises every grouped builder namespace and confirms the immutable
/// snapshot exposes the selected behavior.
#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
#[test]
fn test_grouped_policy_builders_apply_all_namespace_settings() {
    let floor = RedactionFloor::builder()
        .raise("floor_field", Sensitivity::Medium)
        .expect("floor field")
        .build()
        .expect("floor");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .unknown_field_policy(UnknownFieldPolicy::PassThrough)
                .include_preset(SensitiveFieldPreset::AuthTokens)
                .clear_allow_rules()
                .floor(floor.clone())
                .disable_floor();
        })
        .expect("fields")
        .http(|http| {
            http.url_path(UrlPathPolicy::Redact)
                .text_body(TextBodyPolicy::PassThrough)
                .floor_all(floor.clone())
                .disable_all_floors()
                .unkeyed_json(UnkeyedJsonValuePolicy::Redact);
            http.header().disable_floor().clear_allow_rules();
            let _ = http.query().floor(floor.clone());
            http.body().disable_floor();
        })
        .expect("HTTP")
        .uri(|uri| {
            uri.path(UriPathPolicy::Redact).fragment(UriFragmentPolicy::Redact);
        })
        .expect("URI")
        .build()
        .expect("policy");

    assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Redact);
    assert_eq!(policy.http().text_body_policy(), TextBodyPolicy::PassThrough);
    assert_eq!(policy.uri().path_policy(), UriPathPolicy::Redact);
    assert_eq!(policy.uri().fragment_policy(), UriFragmentPolicy::Redact);
    assert!(matches!(
        policy.unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::Redact
    ));
}

/// Verifies every HTTP context mutator returns its validation error and keeps
/// the draft transactional.
#[cfg(feature = "http")]
#[test]
fn test_http_context_builder_rejects_invalid_names_for_every_rule_operation() {
    let results = [
        RedactionPolicy::builder().http(|http| {
            let _ = http.header().raise("_", Sensitivity::High);
        }),
        RedactionPolicy::builder().http(|http| {
            let _ = http.header().override_level("_", Sensitivity::High);
        }),
        RedactionPolicy::builder().http(|http| {
            let _ = http.query().allow_exact("_");
        }),
        RedactionPolicy::builder().http(|http| {
            let _ = http.query().allow_suffix("_");
        }),
        RedactionPolicy::builder().http(|http| {
            let _ = http.body().remove_allow_exact("_");
        }),
        RedactionPolicy::builder().http(|http| {
            let _ = http.body().remove_allow_suffix("_");
        }),
    ];

    assert!(results.into_iter().all(|result| result.is_err()));
}
/// Verifies that an exact allow rule does not allow a contextual suffix.
#[test]
fn test_exact_allow_does_not_allow_contextual_suffix() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .raise("access_token", Sensitivity::High)
                .allow_exact("access_token");
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the exact allow rule should be valid");

    assert_eq!(policy.sensitivity_for("access_token"), None);
    assert_eq!(policy.sensitivity_for("OPENAI_ACCESS_TOKEN"), Some(Sensitivity::High),);
}

/// Verifies that a suffix allow rule explicitly allows contextual suffixes.
#[test]
fn test_suffix_allow_is_explicitly_broad() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor().allow_suffix("access_token");
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the suffix allow rule should be valid");

    assert_eq!(policy.sensitivity_for("access_token"), None);
    assert_eq!(policy.sensitivity_for("OPENAI_ACCESS_TOKEN"), None);
}

/// Verifies overlapping sensitive rules resolve to the strongest level.
#[test]
fn test_overlapping_sensitive_rules_resolve_to_strongest_level() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .override_level("token", Sensitivity::Secret)
                .override_level("access_token", Sensitivity::Medium)
                .matching(FieldNameMatching::ExactOrTokenSuffix);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the sensitivity rules should be valid");

    assert_eq!(policy.sensitivity_for("OPENAI_ACCESS_TOKEN"), Some(Sensitivity::Secret),);
}

/// Verifies that exact matching does not silently use token-suffix lookup.
#[test]
fn test_matching_exact_only_matches_complete_field_name() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .raise("access_token", Sensitivity::High)
                .matching(FieldNameMatching::Exact);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the exact-matching policy should be valid");

    assert_eq!(policy.sensitivity_for("access_token"), Some(Sensitivity::High),);
    assert_eq!(policy.sensitivity_for("OPENAI_ACCESS_TOKEN"), None);
}

/// Verifies that the standard and default policies contain built-in rules.
#[test]
fn test_standard_and_default_contain_presets_and_extra_fields() {
    for policy in [RedactionPolicy::standard(), RedactionPolicy::default()] {
        assert_eq!(policy.sensitivity_for("password"), Some(Sensitivity::Secret),);
        assert_eq!(policy.sensitivity_for("OPENAI_API_KEY"), Some(Sensitivity::High),);
        assert_eq!(policy.sensitivity_for("database_url"), Some(Sensitivity::Secret),);
        assert_eq!(policy.matching(), FieldNameMatching::ExactOrTokenSuffix,);
    }
}

/// Verifies the strict preset redacts unknown application fields.
#[test]
fn test_strict_preset_redacts_unknown_fields() {
    let policy = RedactionPolicy::strict();

    assert_eq!(
        policy.unknown_field_policy(),
        UnknownFieldPolicy::Redact(Sensitivity::Secret),
    );
    assert_eq!(policy.sensitivity_for("custom_field"), Some(Sensitivity::Secret));
}

/// Verifies that ordinary builders have empty application rules and the
/// standard floor.
#[test]
fn test_builder_is_empty_and_default_based_builder_is_explicit() {
    let builder = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise("tenant_id", Sensitivity::Low);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the empty policy should be valid");
    let constructed = RedactionPolicyBuilder::new()
        .fields(|fields| {
            fields.raise("tenant_id", Sensitivity::Low);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the constructed empty policy should be valid");
    let defaulted = RedactionPolicyBuilder::default()
        .fields(|fields| {
            fields.raise("tenant_id", Sensitivity::Low);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the default empty policy should be valid");
    let from_default = RedactionPolicy::default()
        .to_builder()
        .fields(|fields| {
            fields.raise("tenant_id", Sensitivity::Low);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the default-based policy should be valid");
    let copied = from_default
        .to_builder()
        .fields(|fields| {
            fields.include_preset(SensitiveFieldPreset::Session);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the copied policy should be valid");

    assert_eq!(builder.sensitivity_for("password"), Some(Sensitivity::Secret));
    assert_eq!(
        builder
            .application_sensitive_rules()
            .map(|rule| (rule.field(), rule.sensitivity()))
            .collect::<Vec<_>>(),
        vec![("tenantid", Sensitivity::Low)],
    );
    assert_eq!(constructed, builder);
    assert_eq!(defaulted, builder);
    assert_eq!(from_default.sensitivity_for("password"), Some(Sensitivity::Secret));
    assert_eq!(copied.sensitivity_for("session_token"), Some(Sensitivity::High),);
    assert_eq!(copied.sensitivity_for("password"), Some(Sensitivity::Secret));
}

/// Verifies that copying the current snapshot replaces every prior builder
/// state.
#[test]
fn test_builder_from_snapshot_replaces_existing_state_and_error() {
    let policy = RedactionPolicy::default()
        .to_builder()
        .build()
        .expect("the complete default replacement should clear the prior error");

    assert_eq!(policy, RedactionPolicy::default());
    assert_eq!(policy.sensitivity_for("custom_only"), None);
}

/// Verifies that `builder_from` copies every observable policy component.
#[test]
fn test_builder_from_copies_complete_policy_snapshot() {
    let base = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .matching(FieldNameMatching::Exact)
                .mask(Sensitivity::Secret, MaskPolicy::fixed("[copied]"))
                .raise("tenant_secret", Sensitivity::Secret)
                .raise("public_token", Sensitivity::High)
                .raise("diagnostic_token", Sensitivity::Medium)
                .allow_exact("public_token")
                .allow_suffix("diagnostic_token");
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the complete base policy should be valid");
    let copied = base
        .to_builder()
        .build()
        .expect("the copied policy should remain valid");
    let sensitive = copied.application_sensitive_rules().collect::<Vec<_>>();
    let allowed = copied.application_allow_rules().collect::<Vec<_>>();

    assert_eq!(copied.matching(), FieldNameMatching::Exact);
    assert_eq!(copied.masking().mask(Sensitivity::Secret, "secret"), "[copied]",);
    assert_eq!(copied.sensitivity_for("tenant_secret"), Some(Sensitivity::Secret),);
    assert_eq!(copied.sensitivity_for("OPENAI_TENANT_SECRET"), None);
    assert_eq!(copied.sensitivity_for("public_token"), None);
    assert_eq!(copied.sensitivity_for("diagnostic_token"), None);
    assert!(
        sensitive
            .iter()
            .any(|rule| { rule.field() == "publictoken" && rule.sensitivity() == Sensitivity::High })
    );
    assert!(
        sensitive
            .iter()
            .any(|rule| { rule.field() == "diagnostictoken" && rule.sensitivity() == Sensitivity::Medium })
    );
    assert!(
        allowed
            .iter()
            .any(|rule| { rule.field() == "publictoken" && rule.matching() == FieldNameMatching::Exact })
    );
    assert!(
        allowed.iter().any(|rule| {
            rule.field() == "diagnostictoken" && rule.matching() == FieldNameMatching::ExactOrTokenSuffix
        })
    );
}

/// Verifies that raising never weakens a rule while overriding replaces it.
#[test]
fn test_raise_and_override_have_distinct_strength_semantics() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .raise("credential", Sensitivity::High)
                .raise("credential", Sensitivity::Medium)
                .override_level("override", Sensitivity::High)
                .override_level("override", Sensitivity::Low);
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the sensitivity rules should be valid");

    assert_eq!(policy.sensitivity_for("credential"), Some(Sensitivity::High),);
    assert_eq!(policy.sensitivity_for("override"), Some(Sensitivity::Low),);
}

/// Verifies that masking can be replaced and queried by sensitivity level.
#[test]
fn test_mask_replaces_one_masking_policy() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.mask(Sensitivity::Secret, MaskPolicy::fixed("[hidden]"));
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the mask policy should be valid");

    assert_eq!(policy.masking().mask(Sensitivity::Secret, "value"), "[hidden]");
    assert_eq!(policy.masking().mask(Sensitivity::High, "value"), "****");
}

/// Verifies that empty canonical field names are rejected immediately.
#[test]
fn test_setters_reject_empty_canonical_field_names() {
    let expected = Some(PolicyError::EmptyFieldName {
        location: PolicyLocation::Rules,
    });
    for operation in [
        RedactionPolicyBuilder::validate_field_name(" _-.[ ] "),
        RedactionPolicyBuilder::validate_field_name(" _-.[ ] "),
        RedactionPolicyBuilder::validate_field_name(" _-.[ ] "),
        RedactionPolicyBuilder::validate_field_name(" _-.[ ] "),
    ] {
        assert_eq!(operation.err(), expected);
    }
}

/// Verifies direct field-name validation matches builder canonicalization.
#[test]
fn test_validate_field_name_accepts_canonicalizable_names_and_rejects_empty() {
    assert_eq!(RedactionPolicyBuilder::validate_field_name("Tenant-Token"), Ok(()),);
    assert_eq!(
        RedactionPolicyBuilder::validate_field_name(" _-.[ ] "),
        Err(PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules
        }),
    );
}

/// Verifies that fixed masks require a non-empty replacement immediately.
#[test]
fn test_mask_rejects_empty_fixed_replacement_immediately() {
    let error = RedactionPolicy::builder()
        .fields(|fields| {
            fields.mask(Sensitivity::High, MaskPolicy::fixed(""));
        })
        .err();

    assert_eq!(
        error,
        Some(PolicyError::EmptyFixedReplacement {
            location: PolicyLocation::Rules,
            level: Sensitivity::High,
        }),
    );

    assert!(
        RedactionPolicy::builder()
            .fields(|fields| {
                fields.mask(Sensitivity::High, MaskPolicy::empty());
            })
            .expect("the field configuration should be valid")
            .build()
            .is_ok(),
    );
}

/// Verifies empty builders and validation errors expose useful
/// diagnostics.
#[test]
fn test_builder_and_policy_error_display() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor();
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the builder should be valid");
    assert_eq!(policy.sensitivity_for("password"), None);
    assert_eq!(
        PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules
        }
        .to_string(),
        "field name is empty after canonicalization in rules",
    );
    assert_eq!(
        PolicyError::EmptyFixedReplacement {
            location: PolicyLocation::Rules,
            level: Sensitivity::Medium,
        }
        .to_string(),
        "fixed mask replacement for Medium sensitivity is empty in rules",
    );
}

/// Verifies that immutable rule views expose canonical, sorted rule data.
#[test]
fn test_rule_views_expose_canonical_configuration() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .raise("Tenant-Token", Sensitivity::High)
                .allow_exact("Public Token")
                .allow_suffix("Diagnostic.Token");
        })
        .expect("the field configuration should be valid")
        .build()
        .expect("the policy rules should be valid");
    let sensitive = policy.application_sensitive_rules().collect::<Vec<_>>();
    let allowed = policy.application_allow_rules().collect::<Vec<_>>();

    assert_eq!(sensitive.len(), 1);
    assert_eq!(sensitive[0].field(), "tenanttoken");
    assert_eq!(sensitive[0].sensitivity(), Sensitivity::High);
    assert_eq!(allowed.len(), 2);
    assert_eq!(allowed[0].field(), "publictoken");
    assert_eq!(allowed[0].matching(), FieldNameMatching::Exact);
    assert_eq!(allowed[1].field(), "diagnostictoken");
    assert_eq!(allowed[1].matching(), FieldNameMatching::ExactOrTokenSuffix,);
}

/// Verifies every base-field builder operation applies to the isolated draft
/// and that removing allow rules restores the configured sensitivity.
#[test]
fn test_fields_view_applies_and_removes_all_rule_kinds() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .disable_floor()
                .matching(FieldNameMatching::ExactOrTokenSuffix)
                .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::Low))
                .low_sensitive("low")
                .medium_sensitive("medium")
                .high_sensitive("high")
                .secret_sensitive("secret")
                .sensitive(Sensitivity::High, "explicit")
                .raise("raised", Sensitivity::Low)
                .raise("raised", Sensitivity::Secret)
                .override_level("override", Sensitivity::Medium)
                .allow_exact("exact_allowed")
                .allow_suffix("suffix_allowed")
                .remove_allow_exact("exact_allowed")
                .remove_allow_suffix("suffix_allowed")
                .include_preset(SensitiveFieldPreset::Session)
                .mask(Sensitivity::High, MaskPolicy::fixed("[high]"));
        })
        .expect("the complete field draft should be valid")
        .build()
        .expect("the configured policy should build");

    assert_eq!(policy.sensitivity_for("low"), Some(Sensitivity::Low));
    assert_eq!(policy.sensitivity_for("medium"), Some(Sensitivity::Medium));
    assert_eq!(policy.sensitivity_for("high"), Some(Sensitivity::High));
    assert_eq!(policy.sensitivity_for("secret"), Some(Sensitivity::Secret));
    assert_eq!(policy.sensitivity_for("explicit"), Some(Sensitivity::High));
    assert_eq!(policy.sensitivity_for("raised"), Some(Sensitivity::Secret));
    assert_eq!(policy.sensitivity_for("override"), Some(Sensitivity::Medium));
    assert_eq!(policy.sensitivity_for("session_id"), Some(Sensitivity::High));
    assert_eq!(policy.sensitivity_for("exact_allowed"), Some(Sensitivity::Low));
    assert_eq!(policy.sensitivity_for("prefix_suffix_allowed"), Some(Sensitivity::Low));
    assert_eq!(policy.masking().mask(Sensitivity::High, "raw"), "[high]");
}

/// Verifies a field-draft error remains transactional: later calls in the
/// same closure cannot append a partial valid rule.
#[test]
fn test_fields_view_keeps_first_validation_error_and_discards_later_changes() {
    let result = RedactionPolicy::builder().fields(|fields| {
        fields
            .raise("---", Sensitivity::High)
            .secret_sensitive("must_not_be_committed")
            .clear_allow_rules();
    });

    assert_eq!(
        result.err(),
        Some(PolicyError::EmptyFieldName {
            location: PolicyLocation::Rules,
        }),
    );
}

/// Verifies the consuming limits view commits all shared input, output, and
/// structural limits as one immutable policy snapshot.
#[test]
fn test_limits_view_updates_every_shared_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_input_bytes(101)
                .max_output_bytes(53)
                .max_depth(7)
                .max_nodes(11)
                .max_collection_items(13);
        })
        .expect("the limits draft should be valid")
        .build()
        .expect("the limits snapshot should build");
    let limits = policy.limits();

    assert_eq!(limits.max_input_bytes(), 101);
    assert_eq!(limits.max_output_bytes(), 53);
    assert_eq!(limits.max_depth(), Some(7));
    assert_eq!(limits.max_nodes(), Some(11));
    assert_eq!(limits.max_collection_items(), Some(13));
}

/// Verifies the grouped HTTP builder exposes independent header, query, and
/// body rule drafts while retaining its format-wide switches.
#[cfg(feature = "http")]
#[test]
fn test_http_builder_views_apply_context_specific_rules() {
    let policy = RedactionPolicy::builder()
        .http(|http| {
            http.url_path(UrlPathPolicy::Redact)
                .text_body(TextBodyPolicy::PassThrough)
                .floor_all(RedactionFloor::standard())
                .disable_all_floors();

            let mut header = http.header();
            header
                .raise("x-header-secret", Sensitivity::Secret)
                .expect("a header sensitivity rule should be valid");
            header
                .allow_exact("x-header-public")
                .expect("a header allow rule should be valid");
            header
                .remove_allow_exact("x-header-public")
                .expect("removing a header allow rule should be valid");
            header
                .clear_allow_rules()
                .floor(RedactionFloor::standard())
                .disable_floor();

            let mut query = http.query();
            query
                .override_level("query-secret", Sensitivity::High)
                .expect("a query override should be valid");
            query
                .allow_suffix("query-public")
                .expect("a query suffix allow rule should be valid");
            query
                .remove_allow_suffix("query-public")
                .expect("removing a query suffix allow rule should be valid");

            let mut body = http.body();
            body.raise("body-secret", Sensitivity::Medium)
                .expect("a body sensitivity rule should be valid");
        })
        .expect("the HTTP draft should be valid")
        .build()
        .expect("the HTTP policy should build");

    assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Redact);
    assert_eq!(policy.http().text_body_policy(), TextBodyPolicy::PassThrough);
    assert_eq!(
        policy.http().header_rules().sensitivity_for("x-header-secret"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(
        policy.http().query_rules().sensitivity_for("query-secret"),
        Some(Sensitivity::High)
    );
    assert_eq!(
        policy.http().body_rules().sensitivity_for("body-secret"),
        Some(Sensitivity::Medium)
    );
}

proptest! {
    /// Verifies that repeated policy lookup is deterministic for arbitrary names.
    #[test]
    fn test_policy_lookup_is_deterministic(name in ".*") {
        let policy = RedactionPolicy::standard();
        prop_assert_eq!(
            policy.sensitivity_for(&name),
            policy.sensitivity_for(&name),
        );
    }
}
