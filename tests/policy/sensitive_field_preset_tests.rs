// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`SensitiveFieldPreset`](qubit_redact::SensitiveFieldPreset).

use qubit_redact::{
    SensitiveFieldPreset,
    Sensitivity,
};

/// Verifies the complete credentials preset table and its strongest entries.
#[test]
fn test_sensitive_field_preset_credentials_fields() {
    let fields = SensitiveFieldPreset::Credentials.fields();

    assert_eq!(fields.len(), 13);
    assert_eq!(fields[0], ("password", Sensitivity::Secret));
    assert!(fields.contains(&("security_key", Sensitivity::Secret)));
    assert!(fields.contains(&("secret_key", Sensitivity::Secret)));
    assert!(fields.contains(&("secret_access_key", Sensitivity::Secret)));
    assert!(fields.contains(&("access_key", Sensitivity::High)));
    assert!(fields.contains(&("access_key_id", Sensitivity::Medium)));
    assert!(fields.contains(&("passphrase", Sensitivity::Secret)));
    assert!(fields.contains(&("pgpassword", Sensitivity::Secret)));
}

/// Verifies the complete credential-container preset boundaries.
#[test]
fn test_sensitive_field_preset_credential_container_fields() {
    let fields = SensitiveFieldPreset::CredentialContainers.fields();

    assert_eq!(fields.len(), 11);
    assert_eq!(fields[0], ("dsn", Sensitivity::Secret));
    assert_eq!(fields[10], ("docker_auth_config", Sensitivity::Secret),);
}

/// Verifies the complete authentication-token preset boundaries.
#[test]
fn test_sensitive_field_preset_auth_tokens_fields() {
    let fields = SensitiveFieldPreset::AuthTokens.fields();

    assert_eq!(fields.len(), 9);
    assert_eq!(fields[0], ("api_key", Sensitivity::High));
    assert_eq!(fields[8], ("auth_token", Sensitivity::High));
}

/// Verifies the complete HTTP preset boundaries.
#[test]
fn test_sensitive_field_preset_http_fields() {
    let fields = SensitiveFieldPreset::Http.fields();

    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0], ("authorization", Sensitivity::High));
    assert_eq!(fields[3], ("set_cookie", Sensitivity::High));
}

/// Verifies the complete session preset table.
#[test]
fn test_sensitive_field_preset_session_fields() {
    let fields = SensitiveFieldPreset::Session.fields();

    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0], ("session", Sensitivity::High));
    assert_eq!(fields[1], ("session_id", Sensitivity::High));
    assert_eq!(fields[2], ("session_token", Sensitivity::High));
}
