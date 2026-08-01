// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for environment-variable redaction adapters.

mod env;

#[cfg(unix)]
use std::{
    ffi::OsString,
    os::unix::ffi::OsStringExt,
};

use proptest::prelude::{
    prop_assert,
    prop_assert_eq,
    proptest,
};

use qubit_redact::{
    DiagnosticBudget,
    FieldNameMatching,
    RedactionPolicy,
    Redactor,
    Sensitivity,
    env::EnvRedactor,
};

/// Verifies aggregate environment rendering stops before inspecting a pair
/// that exceeds the configured input budget.
#[test]
fn test_redact_os_pairs_stops_before_input_budget_exhaustion() {
    let budget = DiagnosticBudget::new(8, 64)
        .expect("the small diagnostic budget should be valid");
    let policy = RedactionPolicy::empty_builder()
        .diagnostic_budget(budget)
        .build()
        .expect("the bounded policy should be valid");
    let redactor = EnvRedactor::new(Redactor::new(policy));

    let rendered = redactor
        .redact_os_pairs(vec![("MODE".as_ref(), "uninspected-secret".as_ref())])
        .to_string();

    assert!(rendered.len() <= 64, "{rendered}");
    assert!(rendered.contains("truncated"), "{rendered}");
    assert!(!rendered.contains("uninspected-secret"), "{rendered}");
}

/// Verifies aggregate environment rendering stops at the final output budget.
#[test]
fn test_redact_os_pairs_stops_after_output_budget_exhaustion() {
    let budget = DiagnosticBudget::new(8, 64)
        .expect("the small diagnostic budget should be valid");
    let policy = RedactionPolicy::empty_builder()
        .diagnostic_budget(budget)
        .build()
        .expect("the bounded policy should be valid");
    let redactor = EnvRedactor::new(Redactor::new(policy));

    let rendered = redactor
        .redact_os_pairs(vec![
            (
                std::ffi::OsStr::new(""),
                std::ffi::OsStr::new("")
            );
            128
        ])
        .to_string();

    assert!(rendered.len() <= 64, "{rendered}");
    assert!(rendered.ends_with("<truncated>"), "{rendered}");
}

/// Verifies aggregate environment rendering preserves safe assignments within
/// the configured budget.
#[test]
fn test_redact_os_pairs_renders_complete_safe_assignments() {
    let rendered = EnvRedactor::default()
        .redact_os_pairs(vec![
            (std::ffi::OsStr::new("MODE"), std::ffi::OsStr::new("debug")),
            (
                std::ffi::OsStr::new("PASSWORD"),
                std::ffi::OsStr::new("secret"),
            ),
        ])
        .to_string();

    assert_eq!(rendered, r#"["MODE=debug", "PASSWORD=<redacted>"]"#);
}

/// Verifies sensitive values are redacted before log escaping.
#[test]
fn test_redact_pair_display_redacts_and_escapes() {
    let rendered = EnvRedactor::default()
        .redact_pair("PASSWORD", "secret\nnext")
        .to_string();

    assert_eq!(rendered, "PASSWORD=<redacted>");
    assert!(!rendered.contains('\n'));
}

/// Verifies suffix matching classifies prefixed environment names by default.
#[test]
fn test_redact_pair_masks_prefixed_sensitive_name() {
    assert_eq!(
        EnvRedactor::default()
            .redact_pair("OPENAI_API_KEY", "abcdef")
            .to_string(),
        "OPENAI_API_KEY=****",
    );
}

/// Verifies a name that canonicalizes to empty is not classified as sensitive.
#[test]
fn test_redact_pair_ignores_empty_canonical_name() {
    assert_eq!(
        EnvRedactor::default()
            .redact_pair("___", "secret")
            .to_string(),
        "___=secret",
    );
}

/// Verifies the longest matching suffix determines the sensitivity level.
#[test]
fn test_redact_pair_resolves_longest_suffix_match() {
    let policy = RedactionPolicy::empty_builder()
        .raise("key", Sensitivity::Low)
        .raise("api_key", Sensitivity::High)
        .build()
        .expect("the overlapping environment policy should be valid");
    let redactor = EnvRedactor::new(Redactor::new(policy));

    assert_eq!(
        redactor.redact_pair("VENDOR_API_KEY", "abcdef").to_string(),
        "VENDOR_API_KEY=****",
    );
}

/// Verifies an exact-only policy keeps a merely prefixed environment name.
#[test]
fn test_redact_pair_honors_exact_matching_policy() {
    let policy = RedactionPolicy::empty_builder()
        .disable_floor()
        .matching(FieldNameMatching::Exact)
        .build()
        .expect("the exact-only environment policy should be valid");
    let redactor = EnvRedactor::new(Redactor::new(policy));

    assert_eq!(
        redactor.redact_pair("OPENAI_API_KEY", "abcdef").to_string(),
        "OPENAI_API_KEY=abcdef",
    );
}

/// Verifies assignments split only at the first equals sign.
#[test]
fn test_redact_assignment_masks_secret_and_preserves_value_equals() {
    assert_eq!(
        EnvRedactor::default()
            .redact_assignment("PASSWORD=secret=tail")
            .to_string(),
        "PASSWORD=<redacted>",
    );
    assert_eq!(
        EnvRedactor::default()
            .redact_assignment("MODE=debug=tail")
            .to_string(),
        "MODE=debug=tail",
    );
}

/// Verifies text without an equals sign becomes an empty-valued pair.
#[test]
fn test_redact_assignment_renders_missing_value_as_empty() {
    assert_eq!(
        EnvRedactor::default().redact_assignment("PATH").to_string(),
        "PATH=",
    );
}

/// Verifies callers can map the pair-oriented API over assignment iterators.
#[test]
fn test_redact_assignment_maps_over_assignment_iterators() {
    let redactor = EnvRedactor::default();
    let rendered: Vec<_> = ["PASSWORD=secret", "MODE=debug\nforged"]
        .into_iter()
        .map(|assignment| redactor.redact_assignment(assignment).to_string())
        .collect();

    assert_eq!(rendered, ["PASSWORD=<redacted>", r"MODE=debug\nforged"]);
}

/// Verifies non-sensitive values remain visible while controls are escaped.
#[test]
fn test_redact_pair_escapes_non_sensitive_name_and_value() {
    let rendered = EnvRedactor::default()
        .redact_pair("MODE\nFORGED", "debug\nnext\u{202e}")
        .to_string();

    assert!(!rendered.contains('\n'));
    assert!(!rendered.contains('\u{202e}'));
    assert_eq!(rendered, r"MODE\nFORGED=debug\nnext\u{202e}");
}

/// Verifies custom field rules are resolved through the injected policy.
#[test]
fn test_new_uses_custom_redaction_policy() {
    let policy = RedactionPolicy::empty_builder()
        .raise("tenant_value", Sensitivity::Secret)
        .build()
        .expect("the custom environment policy should be valid");
    let redactor = EnvRedactor::new(Redactor::new(policy));

    assert_eq!(
        redactor.redactor().policy().sensitivity_for("tenant_value"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        redactor
            .redact_pair("TENANT_VALUE", "tenant-secret")
            .to_string(),
        "TENANT_VALUE=<redacted>",
    );
}

/// Verifies the OS-pair entry delegates valid UTF-8 components to normal policy
/// lookup.
#[test]
fn test_redact_os_pair_handles_valid_utf8_components() {
    assert_eq!(
        EnvRedactor::default()
            .redact_os_pair("SERVICE_TOKEN".as_ref(), "abcdef".as_ref())
            .to_string(),
        "SERVICE_TOKEN=****",
    );
}

/// Verifies invalid UTF-8 in both components masks the complete value.
#[cfg(unix)]
#[test]
fn test_redact_os_pair_masks_non_utf8_name_and_value() {
    let name = OsString::from_vec(b"CUSTOM_\xFF_KEY".to_vec());
    let value = OsString::from_vec(b"prefix-secret-\xFF-suffix".to_vec());

    let rendered = EnvRedactor::default()
        .redact_os_pair(&name, &value)
        .to_string();

    assert_eq!(rendered, "CUSTOM_�_KEY=<redacted>");
    assert!(!rendered.contains("prefix-secret"));
    assert!(!rendered.contains("suffix"));
}

/// Verifies an invalid UTF-8 name fails closed for an otherwise valid value.
#[cfg(unix)]
#[test]
fn test_redact_os_pair_masks_value_for_non_utf8_name() {
    let name = OsString::from_vec(b"CUSTOM_\xFF_KEY".to_vec());

    let rendered = EnvRedactor::default()
        .redact_os_pair(&name, "plain-secret".as_ref())
        .to_string();

    assert_eq!(rendered, "CUSTOM_�_KEY=<redacted>");
    assert!(!rendered.contains("plain-secret"));
}

/// Verifies an invalid UTF-8 value fails closed for an ordinary name.
#[cfg(unix)]
#[test]
fn test_redact_os_pair_masks_non_utf8_value() {
    let value = OsString::from_vec(b"prefix-secret-\xFF-suffix".to_vec());

    let rendered = EnvRedactor::default()
        .redact_os_pair("MODE".as_ref(), &value)
        .to_string();

    assert_eq!(rendered, "MODE=<redacted>");
    assert!(!rendered.contains("prefix-secret"));
}

/// Verifies bounded aggregate rendering also fails closed for non-UTF-8
/// components.
#[cfg(unix)]
#[test]
fn test_redact_os_pairs_masks_non_utf8_components() {
    let name = OsString::from_vec(b"CUSTOM_\xFF_KEY".to_vec());
    let value = OsString::from_vec(b"prefix-secret-\xFF-suffix".to_vec());

    let rendered = EnvRedactor::default()
        .redact_os_pairs([(&*name, &*value)])
        .to_string();

    assert_eq!(rendered, r#"["CUSTOM_�_KEY=<redacted>"]"#);
    assert!(!rendered.contains("prefix-secret"));
    assert!(!rendered.contains("suffix"));
}

proptest! {
    /// Verifies environment redaction is deterministic and never leaks secrets.
    #[test]
    fn test_redact_assignment_never_leaks_sensitive_value(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let assignment = format!("OPENAI_API_KEY={secret}");
        let first = EnvRedactor::default()
            .redact_assignment(&assignment)
            .to_string();
        let second = EnvRedactor::default()
            .redact_assignment(&assignment)
            .to_string();

        prop_assert!(!first.contains(&secret));
        prop_assert_eq!(first, second);
    }
}
