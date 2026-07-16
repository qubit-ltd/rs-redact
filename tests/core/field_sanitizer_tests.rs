// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`FieldSanitizer`](qubit_sanitize::FieldSanitizer).

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

use qubit_sanitize::{
    FieldSanitizePolicy, FieldSanitizer, MaskPolicies, MaskPolicy, NameMatchMode, SensitiveFields,
    SensitivityLevel,
};

#[test]
fn test_field_sanitizer_sanitize_value_masks_default_sensitive_field() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_value("password", "secret", NameMatchMode::Exact),
        "<redacted>"
    );
}

#[test]
fn test_field_sanitizer_sanitize_value_keeps_non_sensitive_field_borrowed() {
    let sanitizer = FieldSanitizer::default();
    let value = "debug";

    assert_eq!(
        sanitizer.sanitize_value("log_level", value, NameMatchMode::Exact),
        Cow::Borrowed(value)
    );
}

#[test]
fn test_field_sanitizer_sensitivity_for_name_resolves_exact_name() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(
        sanitizer.sensitivity_for_name("access-token", NameMatchMode::Exact),
        Some(SensitivityLevel::High),
    );
}

#[test]
fn test_field_sanitizer_sensitivity_for_name_exact_keeps_suffix_unmatched() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(
        sanitizer.sensitivity_for_name("OPENAI_API_KEY", NameMatchMode::Exact),
        None
    );
}

#[test]
fn test_field_sanitizer_sensitivity_for_name_resolves_suffix() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(
        sanitizer.sensitivity_for_name("OPENAI_API_KEY", NameMatchMode::ExactOrSuffix,),
        Some(SensitivityLevel::High),
    );
}

#[test]
fn test_field_sanitizer_sensitivity_for_name_resolves_token_boundaries() {
    let sanitizer = FieldSanitizer::default();

    for name in [
        "OPENAI_API_KEY",
        "openaiApiKey",
        "openaiAPIKey",
        "openai-api-key",
        "apiKey",
    ] {
        assert_eq!(
            sanitizer.sensitivity_for_name(name, NameMatchMode::ExactOrSuffix),
            Some(SensitivityLevel::High),
            "expected {name:?} to match api_key",
        );
    }
}

#[test]
fn test_sensitive_fields_exact_or_suffix_matches_bracketed_paths() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(
        sanitizer.sensitivity_for_name("user[password]", NameMatchMode::ExactOrSuffix,),
        Some(SensitivityLevel::Secret),
    );
    assert_eq!(
        sanitizer.sensitivity_for_name("credentials[api_key]", NameMatchMode::ExactOrSuffix,),
        Some(SensitivityLevel::High),
    );
    assert_eq!(
        sanitizer.sensitivity_for_name("notpassword", NameMatchMode::ExactOrSuffix,),
        None,
    );
}

#[test]
fn test_field_sanitizer_sensitivity_for_name_resolves_longest_suffix() {
    let mut fields = SensitiveFields::new();
    fields.insert("key", SensitivityLevel::Low);
    fields.insert("api_key", SensitivityLevel::High);
    let sanitizer = FieldSanitizer::new(FieldSanitizePolicy::new(fields, MaskPolicies::default()));

    assert_eq!(
        sanitizer.sensitivity_for_name("VENDOR_API_KEY", NameMatchMode::ExactOrSuffix,),
        Some(SensitivityLevel::High),
    );
}

#[test]
fn test_field_sanitizer_sensitivity_for_name_rejects_unbounded_suffix() {
    let mut fields = SensitiveFields::new();
    fields.insert("key", SensitivityLevel::Low);
    fields.insert("api_key", SensitivityLevel::High);
    let sanitizer = FieldSanitizer::new(FieldSanitizePolicy::new(fields, MaskPolicies::default()));

    assert_eq!(
        sanitizer.sensitivity_for_name("notapikey", NameMatchMode::ExactOrSuffix,),
        None,
    );
    assert_eq!(
        sanitizer.sensitivity_for_name("monkey", NameMatchMode::ExactOrSuffix),
        None,
    );
}

#[test]
fn test_field_sanitizer_sanitize_value_uses_level_specific_policy() {
    let mut fields = SensitiveFields::new();
    fields.insert("session_id", SensitivityLevel::Low);
    fields.insert("license_key", SensitivityLevel::Medium);
    fields.insert("api_key", SensitivityLevel::High);
    fields.insert("private_key", SensitivityLevel::Secret);
    let policy = FieldSanitizePolicy::new(
        fields,
        MaskPolicies::new(
            MaskPolicy::preserve_edges(2, 2, "****", 4),
            MaskPolicy::preserve_suffix(3, "****", 3),
            MaskPolicy::fixed("****"),
            MaskPolicy::fixed("<secret>"),
        ),
    );
    let sanitizer = FieldSanitizer::new(policy);

    assert_eq!(
        sanitizer.sanitize_value("session-id", "abcdef", NameMatchMode::Exact),
        "ab****ef"
    );
    assert_eq!(
        sanitizer.sanitize_value("license-key", "abcdef", NameMatchMode::Exact),
        "****def"
    );
    assert_eq!(
        sanitizer.sanitize_value("api-key", "abcdef", NameMatchMode::Exact),
        "****"
    );
    assert_eq!(
        sanitizer.sanitize_value("private-key", "abcdef", NameMatchMode::Exact),
        "<secret>",
    );
}

#[test]
fn test_field_sanitizer_sanitize_value_masks_suffix_name() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_value("OPENAI_API_KEY", "abcdef", NameMatchMode::ExactOrSuffix,),
        "****",
    );
}

#[test]
fn test_field_sanitizer_credentials_preset_masks_environment_names() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_value("SECRET_KEY", "abcdef", NameMatchMode::ExactOrSuffix,),
        "<redacted>",
    );
    assert_eq!(
        sanitizer.sanitize_value(
            "AWS_SECRET_ACCESS_KEY",
            "abcdef",
            NameMatchMode::ExactOrSuffix,
        ),
        "<redacted>",
    );
    assert_eq!(
        sanitizer.sensitivity_for_name("AWS_ACCESS_KEY", NameMatchMode::ExactOrSuffix,),
        Some(SensitivityLevel::High),
    );
    assert_eq!(
        sanitizer.sanitize_value("AWS_ACCESS_KEY", "abcdef", NameMatchMode::ExactOrSuffix,),
        "****",
    );
    assert_eq!(
        sanitizer.sanitize_value(
            "AWS_ACCESS_KEY_ID",
            "AKIA12345678",
            NameMatchMode::ExactOrSuffix,
        ),
        "****8",
    );
}

#[test]
fn test_field_sanitizer_insert_sensitive_field_extends_policy() {
    let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
    sanitizer.insert_sensitive_field("license_key", SensitivityLevel::Medium);

    assert_eq!(
        sanitizer.sanitize_value("license-key", "abcdef", NameMatchMode::Exact),
        "****f"
    );
}

#[test]
fn test_field_sanitizer_add_and_set_have_distinct_level_semantics() {
    let mut sanitizer = FieldSanitizer::default();

    sanitizer.insert_sensitive_field("password", SensitivityLevel::Low);
    assert_eq!(
        sanitizer.sensitivity_for_name("password", NameMatchMode::Exact),
        Some(SensitivityLevel::Secret),
    );

    sanitizer.set_sensitive_field_level("password", SensitivityLevel::Low);
    assert_eq!(
        sanitizer.sensitivity_for_name("password", NameMatchMode::Exact),
        Some(SensitivityLevel::Low),
    );
}

#[test]
fn test_field_sanitizer_extend_sensitive_fields_keeps_stronger_levels() {
    let mut sanitizer = FieldSanitizer::default();

    sanitizer.extend_sensitive_fields(["password", "custom"], SensitivityLevel::Low);

    assert_eq!(
        sanitizer.sensitivity_for_name("password", NameMatchMode::Exact),
        Some(SensitivityLevel::Secret),
    );
    assert_eq!(
        sanitizer.sensitivity_for_name("custom", NameMatchMode::Exact),
        Some(SensitivityLevel::Low),
    );
}

#[test]
fn test_field_sanitizer_policy_returns_current_policy() {
    let sanitizer = FieldSanitizer::default();

    assert_eq!(
        sanitizer.policy().sensitive_fields().level_for("password"),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_field_sanitizer_policy_mut_customizes_masking() {
    let mut sanitizer = FieldSanitizer::default();
    sanitizer.policy_mut().mask_policies_mut().set(
        SensitivityLevel::High,
        MaskPolicy::preserve_edges(1, 1, "****", 2),
    );

    assert_eq!(
        sanitizer.sanitize_value("api-key", "abcdef", NameMatchMode::Exact),
        "a****f"
    );
}

#[test]
fn test_field_sanitizer_extend_sensitive_fields_adds_multiple_fields() {
    let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
    sanitizer.extend_sensitive_fields(
        ["primary_secret", "secondary_secret"],
        SensitivityLevel::High,
    );

    assert_eq!(
        sanitizer.sanitize_value("primary-secret", "abcdef", NameMatchMode::Exact),
        "****"
    );
    assert_eq!(
        sanitizer.sanitize_value("secondary.secret", "abcdef", NameMatchMode::Exact),
        "****"
    );
}

#[test]
fn test_field_sanitizer_extend_preset_adds_group_fields() {
    let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
    sanitizer.extend_preset(qubit_sanitize::SensitiveFieldPreset::Session);

    assert_eq!(
        sanitizer.sanitize_value("session-id", "abcdef", NameMatchMode::Exact),
        "****f"
    );
    assert_eq!(
        sanitizer.sanitize_value("session-token", "abcdef", NameMatchMode::Exact),
        "****"
    );
}

#[test]
fn test_field_sanitizer_extend_preset_does_not_downgrade_existing_level() {
    let mut sanitizer = FieldSanitizer::new(FieldSanitizePolicy::empty());
    sanitizer.set_sensitive_field_level("authorization", SensitivityLevel::Secret);

    sanitizer.extend_preset(qubit_sanitize::SensitiveFieldPreset::Http);

    assert_eq!(
        sanitizer.sensitivity_for_name("authorization", NameMatchMode::Exact),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_field_sanitizer_sanitize_map_returns_sanitized_copy() {
    let sanitizer = FieldSanitizer::default();
    let mut input = BTreeMap::new();
    input.insert("password".to_string(), "secret".to_string());
    input.insert("name".to_string(), "alice".to_string());

    let output = sanitizer.sanitize_map(&input, NameMatchMode::Exact);

    assert_eq!(
        output.get("password").map(String::as_str),
        Some("<redacted>")
    );
    assert_eq!(output.get("name").map(String::as_str), Some("alice"));
    assert_eq!(input.get("password").map(String::as_str), Some("secret"));
}

#[test]
fn test_field_sanitizer_sanitize_map_in_place_updates_sensitive_values() {
    let sanitizer = FieldSanitizer::default();
    let mut input = BTreeMap::new();
    input.insert("access_token".to_string(), "abcdef".to_string());
    input.insert("mode".to_string(), "debug".to_string());

    sanitizer.sanitize_map_in_place(&mut input, NameMatchMode::Exact);

    assert_eq!(input.get("access_token").map(String::as_str), Some("****"));
    assert_eq!(input.get("mode").map(String::as_str), Some("debug"));
}

#[test]
fn test_field_sanitizer_sanitize_map_masks_suffix_keys() {
    let sanitizer = FieldSanitizer::default();
    let mut input = BTreeMap::new();
    input.insert("OPENAI_API_KEY".to_string(), "abcdef".to_string());
    input.insert("mode".to_string(), "debug".to_string());

    let output = sanitizer.sanitize_map(&input, NameMatchMode::ExactOrSuffix);

    assert_eq!(
        output.get("OPENAI_API_KEY").map(String::as_str),
        Some("****")
    );
    assert_eq!(output.get("mode").map(String::as_str), Some("debug"));
}

#[test]
fn test_field_sanitizer_sanitize_map_in_place_masks_suffix_keys() {
    let sanitizer = FieldSanitizer::default();
    let mut input = BTreeMap::new();
    input.insert("OPENAI_API_KEY".to_string(), "abcdef".to_string());
    input.insert("mode".to_string(), "debug".to_string());

    sanitizer.sanitize_map_in_place(&mut input, NameMatchMode::ExactOrSuffix);

    assert_eq!(
        input.get("OPENAI_API_KEY").map(String::as_str),
        Some("****")
    );
    assert_eq!(input.get("mode").map(String::as_str), Some("debug"));
}

#[test]
fn test_field_sanitizer_sanitize_hash_map_returns_sanitized_copy() {
    let sanitizer = FieldSanitizer::default();
    let mut input = HashMap::new();
    input.insert("password".to_string(), "secret".to_string());
    input.insert("name".to_string(), "alice".to_string());

    let output = sanitizer.sanitize_map(&input, NameMatchMode::Exact);

    assert_eq!(
        output.get("password").map(String::as_str),
        Some("<redacted>")
    );
    assert_eq!(output.get("name").map(String::as_str), Some("alice"));
    assert_eq!(input.get("password").map(String::as_str), Some("secret"));
}

#[test]
fn test_field_sanitizer_sanitize_hash_map_in_place_updates_sensitive_values() {
    let sanitizer = FieldSanitizer::default();
    let mut input = HashMap::new();
    input.insert("access_token".to_string(), "abcdef".to_string());
    input.insert("mode".to_string(), "debug".to_string());

    sanitizer.sanitize_map_in_place(&mut input, NameMatchMode::Exact);

    assert_eq!(input.get("access_token").map(String::as_str), Some("****"));
    assert_eq!(input.get("mode").map(String::as_str), Some("debug"));
}
