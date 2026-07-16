// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`SensitiveFieldPreset`](qubit_sanitize::SensitiveFieldPreset).

use qubit_sanitize::{
    DEFAULT_EXTRA_FIELDS,
    SensitiveFieldPreset,
    SensitiveFields,
    SensitivityLevel,
};

#[test]
fn test_sensitive_field_preset_credentials_fields() {
    let preset_fields = SensitiveFieldPreset::Credentials.fields();
    let mut fields = SensitiveFields::new();
    fields.extend_preset(SensitiveFieldPreset::Credentials);

    assert_eq!(preset_fields.len(), 10);
    assert_eq!(preset_fields[0], ("password", SensitivityLevel::Secret));
    assert_eq!(
        fields.level_for("secret_key"),
        Some(SensitivityLevel::Secret),
    );
    assert_eq!(
        fields.level_for("secret_access_key"),
        Some(SensitivityLevel::Secret),
    );
    assert_eq!(fields.level_for("access_key"), Some(SensitivityLevel::High),);
    assert_eq!(
        fields.level_for("access_key_id"),
        Some(SensitivityLevel::Medium),
    );
}

#[test]
fn test_credentials_preset_contains_security_key_as_secret() {
    let fields = SensitiveFields::default();

    assert_eq!(
        fields.level_for("security_key"),
        Some(SensitivityLevel::Secret),
    );
}

#[test]
fn test_sensitive_field_preset_auth_tokens_fields() {
    let fields = SensitiveFieldPreset::AuthTokens.fields();

    assert_eq!(fields.len(), 9);
    assert_eq!(fields[0], ("api_key", SensitivityLevel::High));
    assert_eq!(fields[8], ("auth_token", SensitivityLevel::High));
}

#[test]
fn test_sensitive_field_preset_http_fields() {
    let fields = SensitiveFieldPreset::Http.fields();

    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0], ("authorization", SensitivityLevel::High));
    assert_eq!(fields[3], ("set_cookie", SensitivityLevel::High));
}

#[test]
fn test_sensitive_field_preset_session_fields() {
    let fields = SensitiveFieldPreset::Session.fields();

    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], ("session", SensitivityLevel::Medium));
    assert_eq!(fields[1], ("session_id", SensitivityLevel::Medium));
    assert_eq!(fields[2], ("session_token", SensitivityLevel::High));
}

#[test]
fn test_sensitive_fields_default_matches_presets_plus_extras() {
    let mut from_presets = SensitiveFields::new();
    for preset in [
        SensitiveFieldPreset::Credentials,
        SensitiveFieldPreset::AuthTokens,
        SensitiveFieldPreset::Http,
        SensitiveFieldPreset::Session,
    ] {
        from_presets.extend_preset(preset);
    }
    for &(field, level) in DEFAULT_EXTRA_FIELDS {
        from_presets.insert_strongest(field, level);
    }

    assert_eq!(from_presets, SensitiveFields::default());
}
