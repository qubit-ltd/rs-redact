// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`ArgvSanitizer`](qubit_sanitize::ArgvSanitizer).

use proptest::prelude::{
    prop_assert,
    proptest,
};

use qubit_sanitize::{
    ArgvSanitizer,
    FieldSanitizer,
    NameMatchMode,
    SensitivityLevel,
};

#[test]
fn test_argv_sanitizer_field_sanitizer_accessors() {
    let mut sanitizer = ArgvSanitizer::default();

    assert!(
        sanitizer
            .field_sanitizer()
            .policy()
            .sensitive_fields
            .contains("password")
    );
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("custom_flag", SensitivityLevel::High);
    assert_eq!(
        sanitizer.sanitize_argv(
            ["cmd", "--custom-flag", "secret"],
            NameMatchMode::ExactOrSuffix
        ),
        ["cmd", "--custom-flag", "****"],
    );
}

#[test]
fn test_argv_sanitizer_masks_sensitive_option_next_value() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            [
                "docker",
                "login",
                "--password",
                "secret",
                "--username",
                "alice"
            ],
            NameMatchMode::ExactOrSuffix
        ),
        [
            "docker",
            "login",
            "--password",
            "<redacted>",
            "--username",
            "alice"
        ],
    );
}

#[test]
fn test_argv_sanitizer_masks_sensitive_inline_option() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["client", "--token=abcdef", "--mode", "debug"],
            NameMatchMode::ExactOrSuffix
        ),
        ["client", "--token=****", "--mode", "debug"],
    );
}

#[test]
fn test_argv_sanitizer_masks_empty_inline_option_value() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["client", "--token=", "mode"],
            NameMatchMode::ExactOrSuffix
        ),
        ["client", "--token=", "mode"],
    );
}

#[test]
fn test_argv_sanitizer_keeps_nonsensitive_inline_option_value() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["client", "--not-sensitive=abcdef"],
            NameMatchMode::ExactOrSuffix
        ),
        ["client", "--not-sensitive=abcdef"],
    );
}

#[test]
fn test_argv_sanitizer_masks_assignment_tokens() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["env", "OPENAI_API_KEY=abcdef", "MODE=debug"],
            NameMatchMode::ExactOrSuffix
        ),
        ["env", "OPENAI_API_KEY=****", "MODE=debug"],
    );
}

#[test]
fn test_argv_sanitizer_exact_mode_keeps_prefixed_assignment_token() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["env", "OPENAI_API_KEY=abcdef"],
            NameMatchMode::Exact
        ),
        ["env", "OPENAI_API_KEY=abcdef"],
    );
}

#[test]
fn test_argv_sanitizer_keeps_shell_payload_unparsed() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["sh", "-c", "echo $OPENAI_API_KEY"],
            NameMatchMode::ExactOrSuffix
        ),
        ["sh", "-c", "echo $OPENAI_API_KEY"],
    );
}

#[test]
fn test_argv_sanitizer_formats_display_string() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv_display(
            ["cmd", "--client-secret", "abcdef"],
            NameMatchMode::ExactOrSuffix
        ),
        r#"["cmd", "--client-secret", "<redacted>"]"#,
    );
}

#[test]
fn test_argv_sanitizer_stops_option_parsing_at_double_dash() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["cmd", "--", "--password", "secret"],
            NameMatchMode::ExactOrSuffix
        ),
        ["cmd", "--", "--password", "secret"],
    );
}

#[test]
fn test_argv_sanitizer_keeps_single_dash_token() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["cmd", "-", "secret"],
            NameMatchMode::ExactOrSuffix
        ),
        ["cmd", "-", "secret"]
    );
}

#[test]
fn test_argv_sanitizer_masks_single_dash_sensitive_option() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["cmd", "-password", "secret"],
            NameMatchMode::ExactOrSuffix
        ),
        ["cmd", "-password", "<redacted>"],
    );
}

#[test]
fn test_argv_sanitizer_ignores_assignment_with_empty_key() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer
            .sanitize_argv(["cmd", "=secret"], NameMatchMode::ExactOrSuffix),
        ["cmd", "=secret"]
    );
}

#[test]
fn test_argv_sanitizer_keeps_option_name_only_dashes() {
    let sanitizer = ArgvSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_argv(
            ["cmd", "---", "value"],
            NameMatchMode::ExactOrSuffix
        ),
        ["cmd", "---", "value"]
    );
}

#[test]
fn test_argv_sanitizer_constructed_from_field_sanitizer() {
    let sanitizer = ArgvSanitizer::new(FieldSanitizer::default());

    assert_eq!(
        sanitizer.sanitize_argv(
            ["cmd", "--token", "abcdef"],
            NameMatchMode::ExactOrSuffix
        ),
        ["cmd", "--token", "****"],
    );
}

proptest! {
    #[test]
    fn test_argv_sanitizer_proptest_never_leaks_sensitive_value(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let sanitizer = ArgvSanitizer::default();
        let sanitized = sanitizer.sanitize_argv(
            ["client", "--password", secret.as_str()],
            NameMatchMode::ExactOrSuffix,
        );

        prop_assert!(!sanitized.iter().any(|arg| arg.contains(&secret)));
    }
}
