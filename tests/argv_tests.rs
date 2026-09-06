// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Transactional argv-redaction integration tests.

mod argv;

use std::ffi::OsStr;

use proptest::prelude::prop_assert;
use proptest::prelude::prop_assert_eq;
use proptest::prelude::proptest;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;

fn explicit<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = ArgvItem<'a>>,
{
    Redactor::standard().redact_argv(items).text().as_str().to_owned()
}

fn heuristic<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = ArgvItem<'a>>,
{
    Redactor::standard()
        .text_composer()
        .argv(|argv| {
            argv.heuristic_items(items);
        })
        .finish()
        .text()
        .as_str()
        .to_owned()
}

#[test]
fn explicit_mode_masks_only_caller_classified_items() {
    let rendered = explicit([
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::sensitive(OsStr::new("raw-secret"), Sensitivity::Secret),
        ArgvItem::plain(OsStr::new("--password")),
    ]);

    assert!(rendered.contains("client"));
    assert!(rendered.contains("--password"));
    assert!(!rendered.contains("raw-secret"));
}

#[test]
fn heuristic_mode_masks_sensitive_options_and_assignments() {
    let rendered = heuristic([
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("separate-secret")),
        ArgvItem::plain(OsStr::new("--token=inline-secret")),
        ArgvItem::plain(OsStr::new("OPENAI_API_KEY=assignment-secret")),
    ]);

    for secret in ["separate-secret", "inline-secret", "assignment-secret"] {
        assert!(!rendered.contains(secret), "{rendered}");
    }
}

#[test]
fn heuristic_does_not_parse_shell_payloads_or_unsupported_compact_forms() {
    let rendered = heuristic([
        ArgvItem::plain(OsStr::new("sh")),
        ArgvItem::plain(OsStr::new("-c")),
        ArgvItem::plain(OsStr::new("echo --password shell-secret")),
        ArgvItem::plain(OsStr::new("-pCOMPACT")),
    ]);

    assert!(rendered.contains("shell-secret"));
    assert!(rendered.contains("-pCOMPACT"));
}

#[test]
fn composer_and_batch_argv_results_are_separate() {
    let text = Redactor::standard()
        .text_composer()
        .literal("argv=")
        .argv(|argv| {
            argv.heuristic_items([
                ArgvItem::plain(OsStr::new("tool")),
                ArgvItem::plain(OsStr::new("--password")),
                ArgvItem::plain(OsStr::new("aggregate-secret")),
            ]);
        })
        .finish();
    let mut batch = Redactor::standard().batch();
    let handle = batch.redact_argv([ArgvItem::sensitive(OsStr::new("item-secret"), Sensitivity::Secret)]);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");

    assert!(text.text().as_str().starts_with("argv="));
    assert!(!text.text().as_str().contains("aggregate-secret"));
    assert!(!output.text(handle).as_str().contains("item-secret"));
}

#[test]
fn direct_argv_handle_operations_publish_explicit_and_heuristic_results() {
    let mut batch = Redactor::standard().batch();
    let explicit_handle = batch.redact_argv([
        ArgvItem::plain(OsStr::new("tool")),
        ArgvItem::sensitive(OsStr::new("explicit-secret"), Sensitivity::Secret),
    ]);
    let heuristic_handle = batch.redact_heuristic_argv([
        ArgvItem::plain(OsStr::new("tool")),
        ArgvItem::plain(OsStr::new("--token")),
        ArgvItem::plain(OsStr::new("heuristic-secret")),
    ]);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");

    assert!(!output.text(explicit_handle).as_str().contains("explicit-secret"));
    assert!(!output.text(heuristic_handle).as_str().contains("heuristic-secret"));
    assert!(output.text(heuristic_handle).as_str().contains("--token"));
}

#[test]
fn exact_output_budget_fill_skips_later_argv_adapter_work() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(4);
        })
        .expect("limits draft")
        .build()
        .expect("policy");
    let output = Redactor::new(policy)
        .text_composer()
        .literal("safe")
        .argv(|argv| {
            argv.heuristic_items([ArgvItem::plain(OsStr::new("--password"))]);
        })
        .finish();

    assert_eq!(output.text().as_str(), "safe");
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(output.summary().usage().output_bytes(), 4);
}

#[cfg(unix)]
#[test]
fn non_utf8_sensitive_items_fail_closed() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let secret = OsString::from_vec(b"prefix-secret-\xff-suffix".to_vec());
    let rendered = explicit([ArgvItem::sensitive(&secret, Sensitivity::Secret)]);

    assert!(!rendered.contains("prefix-secret"));
    assert!(rendered.contains("redacted"));
}

proptest! {
    #[test]
    fn heuristic_redaction_is_deterministic_and_does_not_leak_option_values(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let one = heuristic([
            ArgvItem::plain(OsStr::new("client")),
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new(secret.as_str())),
        ]);
        let two = heuristic([
            ArgvItem::plain(OsStr::new("client")),
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new(secret.as_str())),
        ]);

        prop_assert!(!one.contains(&secret));
        prop_assert_eq!(one, two);
    }
}
