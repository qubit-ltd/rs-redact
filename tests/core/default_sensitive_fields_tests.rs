// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the default sensitive-field collection.

use qubit_redact::{
    SensitiveFieldPreset,
    SensitiveFields,
    SensitivityLevel,
};

#[test]
fn test_sensitive_fields_default_contains_targeted_environment_credentials() {
    let fields = SensitiveFields::default();

    for field in [
        "mysql_pwd",
        "rediscli_auth",
        "database_url",
        "database_uri",
        "connection_string",
    ] {
        assert_eq!(
            fields.level_for(field),
            Some(SensitivityLevel::Secret),
            "expected {field:?} to be secret by default",
        );
    }
}

#[test]
fn test_sensitive_fields_default_contains_credential_containers() {
    let fields = SensitiveFields::default();

    for field in [
        "dsn",
        "redis_url",
        "mongodb_uri",
        "amqp_url",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "docker_auth_config",
    ] {
        assert_eq!(
            fields.level_for(field),
            Some(SensitivityLevel::Secret),
            "expected {field:?} to be secret by default",
        );
    }
}

#[test]
fn test_sensitive_fields_default_matches_presets_plus_extras() {
    let mut from_presets = SensitiveFields::new();
    for preset in [
        SensitiveFieldPreset::Credentials,
        SensitiveFieldPreset::CredentialContainers,
        SensitiveFieldPreset::AuthTokens,
        SensitiveFieldPreset::Http,
        SensitiveFieldPreset::Session,
    ] {
        from_presets.extend_preset(preset);
    }
    for (field, level) in [
        ("auth_app_token", SensitivityLevel::High),
        ("auth_user_token", SensitivityLevel::High),
        ("connection_string", SensitivityLevel::Secret),
        ("database_uri", SensitivityLevel::Secret),
        ("database_url", SensitivityLevel::Secret),
        ("license_key", SensitivityLevel::Medium),
        ("mysql_pwd", SensitivityLevel::Secret),
        ("rediscli_auth", SensitivityLevel::Secret),
        ("sig", SensitivityLevel::Secret),
        ("signature", SensitivityLevel::Secret),
    ] {
        from_presets.insert_strongest(field, level);
    }

    assert_eq!(from_presets, SensitiveFields::default());
}
