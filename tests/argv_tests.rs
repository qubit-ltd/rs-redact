// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the explicit and heuristic argv redaction adapters.

mod argv;

use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use proptest::prelude::prop_assert;
use proptest::prelude::prop_assert_eq;
use proptest::prelude::proptest;
use qubit_redact::FieldNameMatching;
use qubit_redact::InputOutputLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::argv::ArgvItem;
use qubit_redact::argv::ArgvRedactor;
/// Creates a redactor with deliberately small diagnostic limits.
fn bounded_redactor() -> ArgvRedactor {
    let budget = InputOutputLimit::new(8, 64)
        .expect("the small diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the bounded policy should be valid");
    ArgvRedactor::new(Redactor::new(policy))
}

/// Verifies argv rendering stops before inspecting an item beyond the input
/// budget.
#[test]
fn test_redact_items_stops_before_input_budget_exhaustion() {
    let rendered = bounded_redactor()
        .redact_items([ArgvItem::plain(OsStr::new("uninspected-secret"))])
        .to_string();

    assert!(rendered.len() <= 64, "{rendered}");
    assert!(rendered.contains("truncated"), "{rendered}");
    assert!(!rendered.contains("uninspected-secret"), "{rendered}");
}

/// Verifies argv rendering stops after its final log output reaches the budget.
#[test]
fn test_redact_items_stops_after_output_budget_exhaustion() {
    let rendered = bounded_redactor()
        .redact_items(std::iter::repeat_n(ArgvItem::plain(OsStr::new("")), 128))
        .to_string();

    assert!(rendered.len() <= 64, "{rendered}");
    assert!(rendered.ends_with("<truncated>"), "{rendered}");
}

/// Verifies that explicit sensitivity masks a shell payload without parsing it.
#[test]
fn test_redact_items_explicit_sensitivity_is_authoritative() {
    let items = [
        ArgvItem::plain(OsStr::new("sh")),
        ArgvItem::plain(OsStr::new("-c")),
        ArgvItem::sensitive(OsStr::new("echo secret"), Sensitivity::Secret),
    ];

    let rendered = ArgvRedactor::default().redact_items(items).to_string();

    assert!(!rendered.contains("echo secret"));
    assert!(rendered.contains("<redacted>"));
}

/// Verifies that plain mode does not infer option/value roles.
#[test]
fn test_redact_items_does_not_guess_plain_item_roles() {
    let items = [
        ArgvItem::plain(OsStr::new("tool")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("plain-value")),
    ];

    assert_eq!(
        ArgvRedactor::default().redact_items(items).to_string(),
        r#"["tool", "--password", "plain-value"]"#,
    );
}

/// Verifies that heuristic classification applies only to remaining plain
/// items.
#[test]
fn test_redact_heuristically_preserves_explicit_levels_and_matches_plain_options()
 {
    let items = [
        ArgvItem::plain(OsStr::new("tool")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("raw-password")),
        ArgvItem::sensitive(OsStr::new("raw-explicit"), Sensitivity::Secret),
    ];

    let rendered = ArgvRedactor::default()
        .redact_heuristically(items)
        .to_string();

    assert!(!rendered.contains("raw-password"));
    assert!(!rendered.contains("raw-explicit"));
}

/// Verifies separate values of sensitive options are redacted.
#[test]
fn test_redact_heuristically_masks_sensitive_option_next_value() {
    let items = [
        ArgvItem::plain(OsStr::new("docker")),
        ArgvItem::plain(OsStr::new("login")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("secret")),
        ArgvItem::plain(OsStr::new("--username")),
        ArgvItem::plain(OsStr::new("alice")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["docker", "login", "--password", "<redacted>", "--username", "alice"]"#,
    );
}

/// Verifies ambiguous consecutive sensitive options preserve the legacy state
/// machine.
#[test]
fn test_redact_heuristically_masks_consecutive_sensitive_options() {
    let items = [
        ArgvItem::plain(OsStr::new("cmd")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("--token")),
        ArgvItem::plain(OsStr::new("second-secret")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["cmd", "--password", "<redacted>", "****"]"#,
    );
}

/// Verifies inline options and assignment tokens use policy field matching.
#[test]
fn test_redact_heuristically_masks_inline_options_and_assignments() {
    let items = [
        ArgvItem::plain(OsStr::new("env")),
        ArgvItem::plain(OsStr::new("--token=abcdef")),
        ArgvItem::plain(OsStr::new("OPENAI_API_KEY=abcdef")),
        ArgvItem::plain(OsStr::new("MODE=debug")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["env", "--token=****", "OPENAI_API_KEY=****", "MODE=debug"]"#,
    );
}

/// Verifies an empty value on a sensitive inline option remains empty.
#[test]
fn test_redact_heuristically_keeps_empty_sensitive_inline_value() {
    let items = [
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::plain(OsStr::new("--token=")),
        ArgvItem::plain(OsStr::new("mode")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["client", "--token=", "mode"]"#,
    );
}

/// Verifies the default floor protects a suffix-matched assignment even when
/// application matching is exact.
#[test]
fn test_redact_heuristically_floor_classifies_prefixed_assignment_with_exact_application_matching()
 {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().matching(FieldNameMatching::Exact);
        builder
    })
    .build()
    .expect("the exact-only argv policy should be valid");
    let items = [
        ArgvItem::plain(OsStr::new("env")),
        ArgvItem::plain(OsStr::new("OPENAI_API_KEY=abcdef")),
    ];

    assert_eq!(
        ArgvRedactor::new(Redactor::new(policy))
            .redact_heuristically(items)
            .to_string(),
        r#"["env", "OPENAI_API_KEY=****"]"#,
    );
}

/// Verifies an exact single-dash option resolves application-only rules when
/// the caller deliberately disables the floor.
#[test]
fn test_redact_heuristically_uses_application_rule_for_exact_single_dash_option()
 {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().disable_floor();
        builder
            .fields()
            .raise("tenant_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[application]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the application-only argv policy should be valid");
    let items = [
        ArgvItem::plain(OsStr::new("-tenant_secret")),
        ArgvItem::plain(OsStr::new("raw-secret")),
    ];

    assert_eq!(
        ArgvRedactor::new(Redactor::new(policy))
            .redact_heuristically(items)
            .to_string(),
        r#"["-tenant_secret", "[application]"]"#,
    );
}

/// Verifies shell payload text is not parsed internally by heuristic mode.
#[test]
fn test_redact_heuristically_keeps_plain_shell_payload_unparsed() {
    let items = [
        ArgvItem::plain(OsStr::new("sh")),
        ArgvItem::plain(OsStr::new("-c")),
        ArgvItem::plain(OsStr::new("echo $OPENAI_API_KEY")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["sh", "-c", "echo $OPENAI_API_KEY"]"#,
    );
}

/// Verifies an option delimiter remains visible without disabling safety
/// inference for later wrapper arguments.
#[test]
fn test_redact_heuristically_keeps_safety_inference_after_double_dash() {
    let items = [
        ArgvItem::plain(OsStr::new("cmd")),
        ArgvItem::plain(OsStr::new("--")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("plain")),
        ArgvItem::plain(OsStr::new("--password=inline-secret")),
        ArgvItem::plain(OsStr::new("PASSWORD=assignment-secret")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["cmd", "--", "--password", "<redacted>", "--password=<redacted>", "PASSWORD=<redacted>"]"#,
    );
}

/// Verifies wrapper-style argv segments cannot bypass sensitive-option
/// inference after an option delimiter.
#[test]
fn test_redact_heuristically_masks_sensitive_option_after_double_dash() {
    let items = ["cmd", "--", "child", "--password", "raw-secret"]
        .into_iter()
        .map(|value| ArgvItem::plain(OsStr::new(value)));

    let rendered = ArgvRedactor::default()
        .redact_heuristically(items)
        .to_string();

    assert!(!rendered.contains("raw-secret"));
    assert_eq!(
        rendered,
        r#"["cmd", "--", "child", "--password", "<redacted>"]"#,
    );
}

/// Verifies a single dash is not treated as an option name.
#[test]
fn test_redact_heuristically_keeps_single_dash_token() {
    let items = [
        ArgvItem::plain(OsStr::new("cmd")),
        ArgvItem::plain(OsStr::new("-")),
        ArgvItem::plain(OsStr::new("secret")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["cmd", "-", "secret"]"#,
    );
}

/// Verifies one leading dash still supports a configured sensitive option.
#[test]
fn test_redact_heuristically_masks_single_dash_sensitive_option() {
    let items = [
        ArgvItem::plain(OsStr::new("cmd")),
        ArgvItem::plain(OsStr::new("-password")),
        ArgvItem::plain(OsStr::new("secret")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["cmd", "-password", "<redacted>"]"#,
    );
}

/// Verifies a token containing only dashes cannot establish option state.
#[test]
fn test_redact_heuristically_keeps_option_name_only_dashes() {
    let items = [
        ArgvItem::plain(OsStr::new("cmd")),
        ArgvItem::plain(OsStr::new("---")),
        ArgvItem::plain(OsStr::new("value")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["cmd", "---", "value"]"#,
    );
}

/// Verifies explicit metadata prevents a token from changing parser state.
#[test]
fn test_redact_heuristically_does_not_parse_explicit_sensitive_options() {
    let items = [
        ArgvItem::plain(OsStr::new("cmd")),
        ArgvItem::sensitive(OsStr::new("--password"), Sensitivity::Secret),
        ArgvItem::plain(OsStr::new("plain-after-explicit")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["cmd", "<redacted>", "plain-after-explicit"]"#,
    );
}

/// Verifies a custom immutable policy is honored by the adapter.
#[test]
fn test_new_uses_custom_redaction_policy() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("tenant_flag", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the custom argv policy should be valid");
    let redactor = ArgvRedactor::new(Redactor::new(policy));
    let items = [
        ArgvItem::plain(OsStr::new("tool")),
        ArgvItem::plain(OsStr::new("--tenant-flag")),
        ArgvItem::plain(OsStr::new("tenant-secret")),
    ];

    let rendered = redactor.redact_heuristically(items).to_string();

    assert_eq!(
        redactor.redactor().policy().sensitivity_for("tenant_flag"),
        Some(Sensitivity::Secret),
    );
    assert!(!rendered.contains("tenant-secret"));
    assert!(rendered.contains("<redacted>"));
}

/// Verifies malformed and non-sensitive self-contained forms remain unchanged.
#[test]
fn test_redact_heuristically_keeps_unclassified_self_contained_forms() {
    let items = [
        ArgvItem::plain(OsStr::new("cmd")),
        ArgvItem::plain(OsStr::new("=secret")),
        ArgvItem::plain(OsStr::new("---=value")),
        ArgvItem::plain(OsStr::new("--not-sensitive=abcdef")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["cmd", "=secret", "---=value", "--not-sensitive=abcdef"]"#,
    );
}

/// Verifies log controls and bidirectional controls cannot alter output
/// structure.
#[test]
fn test_display_escapes_log_unsafe_plain_items() {
    let items = [ArgvItem::plain(OsStr::new("safe\n\u{202e}forged"))];

    let rendered = ArgvRedactor::default().redact_items(items).to_string();

    assert!(!rendered.contains('\n'));
    assert!(!rendered.contains('\u{202e}'));
    assert!(rendered.contains(r"\n"));
    assert!(rendered.contains(r"\u{202e}"));
}

/// Verifies invalid UTF-8 bytes in an explicit sensitive item never reach
/// output.
#[cfg(unix)]
#[test]
fn test_redact_items_masks_non_utf8_explicit_sensitive_value() {
    let secret = OsString::from_vec(b"prefix-secret-\xFF-suffix".to_vec());
    let items = [ArgvItem::sensitive(&secret, Sensitivity::Low)];

    let rendered = ArgvRedactor::default().redact_items(items).to_string();

    assert_eq!(rendered, r#"["<redacted>"]"#);
    assert!(!rendered.contains("prefix-secret"));
    assert!(!rendered.contains("suffix"));
}

/// Verifies heuristic mode fails closed for an invalid UTF-8 plain token.
#[cfg(unix)]
#[test]
fn test_redact_heuristically_masks_non_utf8_plain_value() {
    let secret = OsString::from_vec(b"prefix-secret-\xFF-suffix".to_vec());
    let items = [ArgvItem::plain(OsStr::new("cmd")), ArgvItem::plain(&secret)];

    let rendered = ArgvRedactor::default()
        .redact_heuristically(items)
        .to_string();

    assert_eq!(rendered, r#"["cmd", "<redacted>"]"#);
    assert!(!rendered.contains("prefix-secret"));
}

/// Verifies a valid sensitive option masks its following non-UTF-8 value.
#[cfg(unix)]
#[test]
fn test_redact_heuristically_masks_non_utf8_sensitive_option_value() {
    let secret = OsString::from_vec(b"prefix-secret-\xFF-suffix".to_vec());
    let items = [
        ArgvItem::plain(OsStr::new("cmd")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(&secret),
    ];

    let rendered = ArgvRedactor::default()
        .redact_heuristically(items)
        .to_string();

    assert_eq!(rendered, r#"["cmd", "--password", "<redacted>"]"#);
    assert!(!rendered.contains("prefix-secret"));
    assert!(!rendered.contains("suffix"));
}

/// Verifies an invalid UTF-8 option also causes its following value to fail
/// closed.
#[cfg(unix)]
#[test]
fn test_redact_heuristically_masks_value_after_non_utf8_option() {
    let option = OsString::from_vec(b"--passw\xFFrd".to_vec());
    let items = [
        ArgvItem::plain(OsStr::new("cmd")),
        ArgvItem::plain(&option),
        ArgvItem::plain(OsStr::new("secret-value")),
    ];

    assert_eq!(
        ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string(),
        r#"["cmd", "<redacted>", "<redacted>"]"#,
    );
}

/// Verifies separate option values use the shared policy mask.
#[test]
fn test_redact_heuristically_uses_application_mask_for_pending_option_value() {
    let floor = RedactionFloor::builder()
        .raise("password", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().floor(floor);
        builder
            .fields()
            .raise("password", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[application]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the policy should build");
    let rendered = ArgvRedactor::new(Redactor::new(policy))
        .redact_heuristically([
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new("value")),
        ])
        .to_string();

    assert_eq!(rendered, r#"["--password", "[application]"]"#);
}

/// Verifies exact single-dash options use the shared policy mask.
#[test]
fn test_redact_heuristically_uses_application_mask_for_exact_single_dash_option()
 {
    let floor = RedactionFloor::builder()
        .raise("tenant_secret", Sensitivity::High)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.fields().floor(floor);
        builder
            .fields()
            .raise("tenant_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[application]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the policy should build");
    let rendered = ArgvRedactor::new(Redactor::new(policy))
        .redact_heuristically([
            ArgvItem::plain(OsStr::new("-tenant_secret")),
            ArgvItem::plain(OsStr::new("value")),
        ])
        .to_string();

    assert_eq!(rendered, r#"["-tenant_secret", "[application]"]"#);
}

proptest! {
    /// Verifies heuristic redaction is deterministic and never leaks option secrets.
    #[test]
    fn test_redact_heuristically_never_leaks_sensitive_value(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let items = [
            ArgvItem::plain(OsStr::new("client")),
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new(secret.as_str())),
        ];
        let first = ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string();
        let second = ArgvRedactor::default()
            .redact_heuristically(items)
            .to_string();

        prop_assert!(!first.contains(&secret));
        prop_assert_eq!(first, second);
    }
}
