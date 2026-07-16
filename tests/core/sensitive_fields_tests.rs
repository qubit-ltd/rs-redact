// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`SensitiveFields`](qubit_sanitize::SensitiveFields).

use qubit_sanitize::{
    SensitiveFieldPreset,
    SensitiveFields,
    SensitivityLevel,
    canonicalize_field_name,
};

#[test]
fn test_canonicalize_field_name_normalizes_common_separators() {
    assert_eq!(canonicalize_field_name(" access_token "), "accesstoken");
    assert_eq!(canonicalize_field_name("access-token"), "accesstoken");
    assert_eq!(canonicalize_field_name("access.token"), "accesstoken");
    assert_eq!(canonicalize_field_name("access Token"), "accesstoken");
    assert_eq!(canonicalize_field_name("accessToken"), "accesstoken");
}

#[test]
fn test_canonicalize_field_name_normalizes_bracket_separators() {
    assert_eq!(canonicalize_field_name("user[password]"), "userpassword");
    assert_eq!(
        canonicalize_field_name("credentials[api_key]"),
        "credentialsapikey",
    );
}

#[test]
fn test_sensitive_fields_default_contains_common_secret_fields() {
    let fields = SensitiveFields::default();

    assert_eq!(fields.level_for("password"), Some(SensitivityLevel::Secret));
    assert_eq!(
        fields.level_for("access-token"),
        Some(SensitivityLevel::High)
    );
    assert_eq!(
        fields.level_for("authorization"),
        Some(SensitivityLevel::High)
    );
}

#[test]
fn test_sensitive_fields_insert_adds_custom_field() {
    let mut fields = SensitiveFields::new();
    fields.insert("license_key", SensitivityLevel::Medium);

    assert_eq!(
        fields.level_for("license-key"),
        Some(SensitivityLevel::Medium),
    );
}

#[test]
fn test_sensitive_fields_insert_strongest_never_lowers_existing_level() {
    let mut fields = SensitiveFields::new();
    fields.insert("password", SensitivityLevel::Secret);

    fields.insert_strongest("Password", SensitivityLevel::Low);

    assert_eq!(fields.level_for("password"), Some(SensitivityLevel::Secret),);
}

#[test]
fn test_sensitive_fields_extend_strongest_merges_each_field() {
    let mut fields = SensitiveFields::new();
    fields.insert("first", SensitivityLevel::High);

    fields.extend_strongest(["First", "second"], SensitivityLevel::Medium);

    assert_eq!(fields.level_for("first"), Some(SensitivityLevel::High));
    assert_eq!(fields.level_for("second"), Some(SensitivityLevel::Medium),);
}

#[test]
fn test_sensitive_fields_remove_uses_canonical_name() {
    let mut fields = SensitiveFields::new();
    fields.insert("api_key", SensitivityLevel::High);

    assert_eq!(fields.remove(" API-Key "), Some(SensitivityLevel::High),);
    assert!(fields.is_empty());
    assert_eq!(fields.remove(" -_. "), None);
}

#[test]
fn test_sensitive_fields_clear_removes_all_fields() {
    let mut fields = SensitiveFields::new();
    fields.insert("api_key", SensitivityLevel::High);
    fields.insert("password", SensitivityLevel::Secret);

    fields.clear();

    assert!(fields.is_empty());
    assert_eq!(fields.len(), 0);
}

#[test]
fn test_sensitive_fields_merge_strongest_keeps_highest_level() {
    let mut target = SensitiveFields::new();
    target.insert("authorization", SensitivityLevel::High);
    target.insert("session_id", SensitivityLevel::Medium);
    let mut source = SensitiveFields::new();
    source.insert("Authorization", SensitivityLevel::Low);
    source.insert("session-id", SensitivityLevel::High);
    source.insert("password", SensitivityLevel::Secret);

    target.merge_strongest(&source);

    assert_eq!(
        target.level_for("authorization"),
        Some(SensitivityLevel::High),
    );
    assert_eq!(target.level_for("session_id"), Some(SensitivityLevel::High),);
    assert_eq!(target.level_for("password"), Some(SensitivityLevel::Secret),);
}

#[test]
fn test_sensitive_fields_from_iterator_normalizes_and_overwrites_duplicates() {
    let fields = [
        ("api-key", SensitivityLevel::Low),
        ("api_key", SensitivityLevel::High),
        ("password", SensitivityLevel::Secret),
    ]
    .into_iter()
    .collect::<SensitiveFields>();

    assert_eq!(fields.len(), 2);
    assert_eq!(fields.level_for("api.key"), Some(SensitivityLevel::High));
    assert_eq!(fields.level_for("password"), Some(SensitivityLevel::Secret));
}

#[test]
fn test_sensitive_fields_from_iterator_accepts_owned_names() {
    let fields = vec![("client_secret".to_string(), SensitivityLevel::Secret)]
        .into_iter()
        .collect::<SensitiveFields>();

    assert_eq!(
        fields.level_for("client-secret"),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_sensitive_fields_ignores_empty_field_name() {
    let mut fields = SensitiveFields::new();
    fields.insert(" -_. ", SensitivityLevel::Secret);

    assert!(fields.is_empty());
}

#[test]
fn test_sensitive_fields_contains_len_and_is_empty_track_entries() {
    let mut fields = SensitiveFields::new();

    assert!(fields.is_empty());
    assert_eq!(fields.len(), 0);
    assert!(!fields.contains("api-key"));

    fields.insert("api-key", SensitivityLevel::High);

    assert!(!fields.is_empty());
    assert_eq!(fields.len(), 1);
    assert!(fields.contains("api_key"));
}

#[test]
fn test_sensitive_fields_extend_adds_multiple_custom_fields() {
    let mut fields = SensitiveFields::new();

    fields.extend(["first_secret", "second_secret"], SensitivityLevel::Secret);

    assert_eq!(
        fields.level_for("first-secret"),
        Some(SensitivityLevel::Secret),
    );
    assert_eq!(
        fields.level_for("second.secret"),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_sensitive_fields_extend_preset_adds_related_names() {
    let mut fields = SensitiveFields::new();
    fields.extend_preset(SensitiveFieldPreset::Http);

    assert_eq!(fields.level_for("set_cookie"), Some(SensitivityLevel::High));
    assert_eq!(
        fields.level_for("proxy-authorization"),
        Some(SensitivityLevel::High),
    );
}

#[test]
fn test_sensitive_fields_extend_preset_does_not_downgrade_existing_level() {
    let mut fields = SensitiveFields::new();
    fields.insert("authorization", SensitivityLevel::Secret);

    fields.extend_preset(SensitiveFieldPreset::Http);

    assert_eq!(
        fields.level_for("authorization"),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_sensitive_fields_extend_preset_covers_all_groups() {
    let mut fields = SensitiveFields::new();

    fields.extend_preset(SensitiveFieldPreset::Credentials);
    fields.extend_preset(SensitiveFieldPreset::AuthTokens);
    fields.extend_preset(SensitiveFieldPreset::Session);

    assert_eq!(
        fields.level_for("client-secret"),
        Some(SensitivityLevel::Secret),
    );
    assert_eq!(
        fields.level_for("refresh-token"),
        Some(SensitivityLevel::High),
    );
    assert_eq!(fields.level_for("jwt-token"), Some(SensitivityLevel::High));
    assert_eq!(
        fields.level_for("session-id"),
        Some(SensitivityLevel::Medium)
    );
    assert_eq!(
        fields.level_for("session-token"),
        Some(SensitivityLevel::High),
    );
}

#[test]
fn test_sensitive_fields_iter_returns_canonical_names() {
    let mut fields = SensitiveFields::new();
    fields.insert("api-key", SensitivityLevel::High);

    let entries = fields.iter().collect::<Vec<_>>();

    assert_eq!(entries, vec![("apikey", SensitivityLevel::High)]);
}
