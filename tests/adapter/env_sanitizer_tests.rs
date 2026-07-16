// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`EnvSanitizer`](qubit_sanitize::EnvSanitizer).

use std::borrow::Cow;

use proptest::prelude::{prop_assert, proptest};

use qubit_sanitize::{
    EnvSanitizer, FieldSanitizePolicy, FieldSanitizer, MaskPolicies, NameMatchMode,
    SensitiveFields, SensitivityLevel,
};

#[test]
fn test_env_sanitizer_field_sanitizer_accessors() {
    let mut sanitizer = EnvSanitizer::default();

    assert!(
        sanitizer
            .field_sanitizer()
            .policy()
            .sensitive_fields()
            .contains("password")
    );
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("custom_env", SensitivityLevel::High);
    assert_eq!(
        sanitizer.sanitize_value("custom_env", "secret", NameMatchMode::ExactOrSuffix),
        "****"
    );
}

#[test]
fn test_env_sanitizer_masks_prefixed_sensitive_key() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_value("OPENAI_API_KEY", "abcdef", NameMatchMode::ExactOrSuffix),
        "****"
    );
}

#[test]
fn test_env_sanitizer_exact_mode_keeps_prefixed_sensitive_key() {
    let sanitizer = EnvSanitizer::default();
    let value = "abcdef";

    assert_eq!(
        sanitizer.sanitize_value("OPENAI_API_KEY", value, NameMatchMode::Exact),
        Cow::Borrowed(value),
    );
}

#[test]
fn test_env_sanitizer_sanitize_assignment_masks_secret() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_assignment("PASSWORD=secret", NameMatchMode::ExactOrSuffix),
        "PASSWORD=<redacted>",
    );
}

#[test]
fn test_env_sanitizer_keeps_non_assignment_unchanged() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_assignment("PATH", NameMatchMode::ExactOrSuffix),
        "PATH"
    );
}

#[test]
fn test_env_sanitizer_sanitize_os_pair_renders_lossy_pair() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_os_pair("SERVICE_TOKEN", "abcdef", NameMatchMode::ExactOrSuffix),
        ("SERVICE_TOKEN".to_string(), "****".to_string()),
    );
}

#[test]
fn test_env_sanitizer_sanitize_pair_preserves_key() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_pair("OPENAI_API_KEY", "abcdef", NameMatchMode::ExactOrSuffix),
        ("OPENAI_API_KEY".to_string(), "****".to_string()),
    );
}

#[test]
fn test_env_sanitizer_sanitize_assignments() {
    let sanitizer = EnvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_assignments(
            ["PASSWORD=secret", "MODE=debug"],
            NameMatchMode::ExactOrSuffix
        ),
        ["PASSWORD=<redacted>", "MODE=debug"],
    );
}

#[test]
fn test_env_sanitizer_keeps_non_sensitive_key_borrowed() {
    let sanitizer = EnvSanitizer::default();
    let value = "debug";

    assert_eq!(
        sanitizer.sanitize_value("LOG_LEVEL", value, NameMatchMode::ExactOrSuffix),
        Cow::Borrowed(value),
    );
}

#[test]
fn test_env_sanitizer_ignores_empty_canonical_name() {
    let sanitizer = EnvSanitizer::default();
    let value = "secret";

    assert_eq!(
        sanitizer.sanitize_value("___", value, NameMatchMode::ExactOrSuffix),
        Cow::Borrowed(value),
    );
}

#[test]
fn test_env_sanitizer_resolves_longest_suffix_match() {
    let mut fields = SensitiveFields::new();
    fields.insert("key", SensitivityLevel::Low);
    fields.insert("api_key", SensitivityLevel::High);
    let sanitizer = EnvSanitizer::new(FieldSanitizer::new(FieldSanitizePolicy::new(
        fields,
        MaskPolicies::default(),
    )));

    assert_eq!(
        sanitizer.sanitize_value("VENDOR_API_KEY", "abcdef", NameMatchMode::ExactOrSuffix),
        "****"
    );
}

#[test]
fn test_env_sanitizer_constructed_from_field_sanitizer() {
    let sanitizer = EnvSanitizer::new(FieldSanitizer::default());

    assert_eq!(
        sanitizer.sanitize_value("PASSWORD", "secret", NameMatchMode::ExactOrSuffix),
        "<redacted>"
    );
}

proptest! {
    #[test]
    fn test_env_sanitizer_proptest_never_leaks_sensitive_value(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let sanitizer = EnvSanitizer::default();
        let assignment = format!("OPENAI_API_KEY={secret}");
        let sanitized = sanitizer.sanitize_assignment(
            &assignment,
            NameMatchMode::ExactOrSuffix,
        );

        prop_assert!(!sanitized.contains(&secret));
    }
}
