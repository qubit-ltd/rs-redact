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
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;

fn explicit<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = ArgvItem<'a>>,
    I::IntoIter: ExactSizeIterator,
{
    Redactor::standard().redact_argv(items).text().as_str().to_owned()
}

fn heuristic<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = ArgvItem<'a>>,
    I::IntoIter: ExactSizeIterator,
{
    let mut session = Redactor::standard().session();
    session.argv(|argv| {
        argv.heuristic_items(items);
    });
    session.finish().text().as_str().to_owned()
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
fn aggregate_and_individual_argv_results_share_one_transaction() {
    let mut session = Redactor::standard().session();
    session.literal("argv=").argv(|argv| {
        argv.heuristic_items([
            ArgvItem::plain(OsStr::new("tool")),
            ArgvItem::plain(OsStr::new("--password")),
            ArgvItem::plain(OsStr::new("aggregate-secret")),
        ]);
    });
    let handle = session.redact_argv([ArgvItem::sensitive(OsStr::new("item-secret"), Sensitivity::Secret)]);
    let output = session.finish();

    assert!(output.text().as_str().starts_with("argv="));
    assert!(!output.text().as_str().contains("aggregate-secret"));
    assert!(
        !output
            .resolve(handle)
            .expect("current handle")
            .text()
            .as_str()
            .contains("item-secret")
    );
}

#[test]
fn direct_argv_handle_operations_publish_explicit_and_heuristic_results() {
    let mut session = Redactor::standard().session();
    let mut explicit_handle = None;
    let mut heuristic_handle = None;
    session.argv(|argv| {
        explicit_handle = Some(argv.redact_items([
            ArgvItem::plain(OsStr::new("tool")),
            ArgvItem::sensitive(OsStr::new("explicit-secret"), Sensitivity::Secret),
        ]));
        heuristic_handle = Some(argv.redact_heuristic_items([
            ArgvItem::plain(OsStr::new("tool")),
            ArgvItem::plain(OsStr::new("--token")),
            ArgvItem::plain(OsStr::new("heuristic-secret")),
        ]));
    });
    let output = session.finish();

    let explicit = output
        .resolve(explicit_handle.expect("explicit handle should be returned"))
        .expect("explicit handle should publish");
    let heuristic = output
        .resolve(heuristic_handle.expect("heuristic handle should be returned"))
        .expect("heuristic handle should publish");
    assert!(!explicit.text().as_str().contains("explicit-secret"));
    assert!(!heuristic.text().as_str().contains("heuristic-secret"));
    assert!(heuristic.text().as_str().contains("--token"));
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
    let mut session = Redactor::new(policy).session();
    session.literal("safe").argv(|argv| {
        argv.heuristic_items([ArgvItem::plain(OsStr::new("--password"))]);
    });
    let output = session.finish();

    assert_eq!(output.text().as_str(), "safe");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
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
