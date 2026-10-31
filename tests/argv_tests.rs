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
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use proptest::prelude::prop_assert;
use proptest::prelude::prop_assert_eq;
use proptest::prelude::proptest;
use qubit_redact::MaskPolicy;
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

#[cfg(unix)]
#[test]
fn test_non_unicode_plain_argv_differs_between_modes() {
    let value = OsString::from_vec(b"visible-secret\xff".to_vec());
    let explicit_output = explicit([ArgvItem::plain(&value)]);
    let heuristic_output = heuristic([ArgvItem::plain(&value)]);
    assert_eq!(explicit_output, "[\"visible-secret�\"]");
    assert_eq!(heuristic_output, "[\"<redacted>\"]");
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
fn test_heuristic_inline_join_shapes_preserve_debug_escaping() {
    let mask = "quote\" slash\\ newline\n snow雪";
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.mask(Sensitivity::Secret, MaskPolicy::fixed(mask));
        })
        .expect("field draft should build")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);

    for input in ["--password=raw", "password=raw", "-Dpassword=raw"] {
        let output = redactor.redact_heuristic_argv([ArgvItem::plain(OsStr::new(input))]);
        let joined = match input {
            "--password=raw" => format!("--password={mask}"),
            "password=raw" => format!("password={mask}"),
            "-Dpassword=raw" => format!("-Dpassword={mask}"),
            _ => unreachable!(),
        };
        assert_eq!(output.text().as_str(), format!("[{joined:?}]"));
        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
        assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    }
}

#[test]
fn test_heuristic_inline_join_budget_failures_keep_batch_marker_and_provenance() {
    const MARKER: &str = "<argv incomplete>";

    for max_output_bytes in [0, 11] {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_output_bytes(max_output_bytes);
            })
            .expect("limit draft should build")
            .build()
            .expect("policy should build");
        let mut batch = Redactor::new(policy).diagnostic_batch();
        let handles = [
            batch.redact_heuristic_argv([ArgvItem::plain(OsStr::new("--password=raw"))]),
            batch.redact_heuristic_argv([ArgvItem::plain(OsStr::new("password=raw"))]),
            batch.redact_heuristic_argv([ArgvItem::plain(OsStr::new("-Dpassword=raw"))]),
        ];
        let output = batch.finish_with_marker(MARKER);

        assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
        assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert!(output.summary().usage().output_bytes() <= max_output_bytes);
        for handle in handles {
            assert_eq!(output.text(handle).as_str(), MARKER);
        }
    }
}

#[test]
fn test_pending_medium_does_not_weaken_secret_inline_items() {
    let redactor = Redactor::standard();
    for inline in ["--password=raw-secret", "PASSWORD=raw-secret", "-Dpassword=raw-secret"] {
        let items = [
            ArgvItem::plain(OsStr::new("--access-key-id")),
            ArgvItem::plain(OsStr::new(inline)),
        ];
        let output = redactor.redact_heuristic_argv(items);
        assert_eq!(output.text().as_str(), r#"["--access-key-id", "<redacted>"]"#);
        let inspection = redactor.inspect_heuristic_argv(items).expect("complete inspection");
        assert_eq!(inspection.max_sensitivity(), Some(Sensitivity::Secret));
        assert_eq!(inspection.usage().output_bytes(), 0);
        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_heuristic_argv(items);
        let published = batch.finish();
        assert_eq!(published.text(handle).as_str(), output.text().as_str());
        let composed = redactor
            .text_composer()
            .argv(|argv| {
                argv.heuristic_items(items);
            })
            .finish();
        assert_eq!(composed.text().as_str(), output.text().as_str());
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
    let mut batch = Redactor::standard().diagnostic_batch();
    let handle = batch.redact_argv([ArgvItem::sensitive(OsStr::new("item-secret"), Sensitivity::Secret)]);
    let output = batch.finish_with_marker("<redaction incomplete>");

    assert!(text.text().as_str().starts_with("argv="));
    assert!(!text.text().as_str().contains("aggregate-secret"));
    assert!(!output.text(handle).as_str().contains("item-secret"));
}

#[test]
fn direct_argv_handle_operations_publish_explicit_and_heuristic_results() {
    let mut batch = Redactor::standard().diagnostic_batch();
    let explicit_handle = batch.redact_argv([
        ArgvItem::plain(OsStr::new("tool")),
        ArgvItem::sensitive(OsStr::new("explicit-secret"), Sensitivity::Secret),
    ]);
    let heuristic_handle = batch.redact_heuristic_argv([
        ArgvItem::plain(OsStr::new("tool")),
        ArgvItem::plain(OsStr::new("--token")),
        ArgvItem::plain(OsStr::new("heuristic-secret")),
    ]);
    let output = batch.finish_with_marker("<redaction incomplete>");

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

#[test]
fn pending_option_semantics_survive_cached_classification() {
    let redactor = Redactor::standard();
    let exact = [
        ArgvItem::plain(OsStr::new("-password")),
        ArgvItem::plain(OsStr::new("exact-secret")),
    ];
    assert!(
        !redactor
            .redact_heuristic_argv(exact)
            .text()
            .as_str()
            .contains("exact-secret")
    );
    assert_eq!(
        redactor
            .inspect_heuristic_argv(exact)
            .expect("exact option inspection")
            .max_sensitivity(),
        Some(Sensitivity::Secret)
    );

    let cleared = [
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::sensitive(OsStr::new("explicit-secret"), Sensitivity::Secret),
        ArgvItem::plain(OsStr::new("visible-after-explicit")),
    ];
    let rendered = redactor.redact_heuristic_argv(cleared);
    assert!(rendered.text().as_str().contains("visible-after-explicit"));
    assert!(!rendered.text().as_str().contains("explicit-secret"));

    let disabled = Redactor::new(RedactionPolicy::disabled());
    let restored = disabled.redact_heuristic_argv([
        ArgvItem::plain(OsStr::new("--password")),
        ArgvItem::plain(OsStr::new("disabled-secret")),
    ]);
    assert!(restored.text().as_str().contains("disabled-secret"));

    let trailing = [ArgvItem::plain(OsStr::new("--password"))];
    assert_eq!(
        redactor.redact_heuristic_argv(trailing).summary().completion(),
        RedactionCompletion::Complete
    );
    assert!(redactor.inspect_heuristic_argv(trailing).is_ok());
}
