// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Windows OS-string redaction contracts through the public API.

#![cfg(windows)]

use std::ffi::OsStr;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;

fn wide(units: &[u16]) -> OsString {
    OsString::from_wide(units)
}

fn bounded_redactor(maximum: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(maximum);
        })
        .expect("valid output limit")
        .build()
        .expect("valid policy");
    Redactor::new(policy)
}

#[test]
fn test_plain_argv_preserves_windows_lossy_representation() {
    for (units, expected, env_expected) in [
        (vec![0x41, 0xD800, 0x42], "[\"A�B\"]", "VISIBLE=A�B"),
        (vec![0x41, 0xDC00, 0x42], "[\"A�B\"]", "VISIBLE=A�B"),
        (vec![0xD83D, 0xDE00], "[\"😀\"]", "VISIBLE=😀"),
    ] {
        let value = wide(&units);
        let output = Redactor::standard().redact_argv([ArgvItem::plain(&value)]);
        assert_eq!(output.text().as_str(), expected);
        assert!(output.text().as_str().is_char_boundary(output.text().as_str().len()));
        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
        assert_eq!(output.summary().usage().output_bytes(), expected.len());

        let standard_env = Redactor::standard().redact_env_pairs([(OsStr::new("VISIBLE"), value.as_os_str())]);
        assert_eq!(standard_env.text().as_str(), env_expected);

        let disabled = Redactor::new(RedactionPolicy::disabled());
        let disabled_argv = disabled.redact_argv([ArgvItem::plain(&value)]);
        assert!(disabled_argv.summary().is_redaction_disabled());
        assert!(
            disabled_argv
                .text()
                .as_str()
                .is_char_boundary(disabled_argv.text().as_str().len())
        );
        let disabled_env = disabled.redact_env_pairs([(OsStr::new("VISIBLE"), value.as_os_str())]);
        assert!(disabled_env.summary().is_redaction_disabled());
        assert_eq!(disabled_env.text().as_str(), env_expected);
    }
}

#[test]
fn test_windows_os_string_output_byte_boundaries() {
    for (units, expected, limits) in [
        (vec![0xD800], "[\"�\"]", vec![0, 2, 3, 4, 6, 7, 8, 11, 12]),
        (vec![0xD83D, 0xDE00], "[\"😀\"]", vec![0, 2, 3, 4, 6, 7, 8, 11, 12]),
    ] {
        for maximum in limits {
            let value = wide(&units);
            let output = bounded_redactor(maximum).redact_argv([ArgvItem::plain(&value)]);
            let summary = output.summary();
            assert!(
                summary.usage().output_bytes() <= maximum,
                "limit={maximum}, output={:?}",
                output.text()
            );
            assert_eq!(output.text().as_str().len(), summary.usage().output_bytes());
            if maximum >= expected.len() {
                assert_eq!(output.text().as_str(), expected, "limit={maximum}");
                assert_eq!(summary.completion(), RedactionCompletion::Complete);
            } else {
                assert_ne!(summary.completion(), RedactionCompletion::Complete, "limit={maximum}");
                assert!(
                    summary.reasons().contains(RedactionReason::OutputLimitReached),
                    "limit={maximum}"
                );
            }
        }
    }
}

#[test]
fn test_windows_non_unicode_values_are_redacted_and_inspected_conservatively() {
    const SENTINEL: &str = "windows-secret-427b93";
    let mut secret_units: Vec<_> = SENTINEL.encode_utf16().collect();
    secret_units.push(0xD800);
    let secret = wide(&secret_units);
    let name = OsString::from("PASSWORD");
    let opaque_name = wide(&[b'N' as u16, 0xD800]);

    let explicit = Redactor::standard().redact_argv([ArgvItem::sensitive(secret.as_os_str(), Sensitivity::Secret)]);
    assert!(!explicit.text().as_str().contains(SENTINEL));
    assert!(
        explicit
            .text()
            .as_str()
            .is_char_boundary(explicit.text().as_str().len())
    );

    let heuristic = Redactor::standard().redact_heuristic_argv([ArgvItem::plain(secret.as_os_str())]);
    assert!(!heuristic.text().as_str().contains(SENTINEL));

    let env = Redactor::standard().redact_env_pairs([(name.as_os_str(), secret.as_os_str())]);
    assert!(!env.text().as_str().contains(SENTINEL));
    let opaque_env = Redactor::standard().redact_env_pairs([(opaque_name.as_os_str(), secret.as_os_str())]);
    assert!(!opaque_env.text().as_str().contains(SENTINEL));

    let inspection = Redactor::standard()
        .inspect_env_pairs([(opaque_name.as_os_str(), secret.as_os_str())])
        .expect("non-Unicode environment name is conclusively secret");
    assert_eq!(inspection.max_sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(inspection.usage().output_bytes(), 0);

    let ordinary_name = OsStr::new("VISIBLE");
    let ordinary_env = Redactor::standard().redact_env_pairs([(ordinary_name, secret.as_os_str())]);
    assert!(!ordinary_env.text().as_str().contains(SENTINEL));
    assert!(ordinary_env.text().as_str().contains("redacted"));
    let ordinary_inspection = Redactor::standard()
        .inspect_env_pairs([(ordinary_name, secret.as_os_str())])
        .expect("ordinary environment name is classifiable");
    assert_eq!(ordinary_inspection.max_sensitivity(), None);
    assert_eq!(ordinary_inspection.usage().output_bytes(), 0);

    let disabled = Redactor::new(RedactionPolicy::disabled());
    let disabled_argv = disabled.redact_argv([ArgvItem::plain(secret.as_os_str())]);
    assert!(disabled_argv.summary().is_redaction_disabled());
    assert!(disabled_argv.text().as_str().contains(&format!("{SENTINEL}�")));
    let disabled_env = disabled.redact_env_pairs([(ordinary_name, secret.as_os_str())]);
    assert!(disabled_env.summary().is_redaction_disabled());
    assert!(disabled_env.text().as_str().contains(&format!("{SENTINEL}�")));
}

#[test]
fn test_windows_os_string_composer_batch_and_process_paths() {
    const SENTINEL: &str = "windows-secret-427b93";
    let mut value_units: Vec<_> = SENTINEL.encode_utf16().collect();
    value_units.push(0xD800);
    let value = wide(&value_units);
    let mut program_units: Vec<_> = "program".encode_utf16().collect();
    program_units.push(0xD800);
    let program = wide(&program_units);
    let name = OsStr::new("PASSWORD");

    let composed = Redactor::standard()
        .text_composer()
        .argv(|argv| {
            let _ = argv.items([ArgvItem::sensitive(value.as_os_str(), Sensitivity::Secret)]);
        })
        .finish();
    assert!(!composed.text().as_str().contains(SENTINEL));
    assert_eq!(
        composed.text().as_str().len(),
        composed.summary().usage().output_bytes()
    );

    let mut batch = bounded_redactor(4).diagnostic_batch();
    let handle = batch.redact_argv([ArgvItem::plain(value.as_os_str())]);
    let published = batch.finish_with_marker("<incomplete>");
    assert_eq!(published.text(handle).as_str(), "<incomplete>");
    assert!(published.summary().usage().output_bytes() <= 4);
    assert!(
        published
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );

    let output = Redactor::standard().redact_process(
        program.as_os_str(),
        [ArgvItem::sensitive(value.as_os_str(), Sensitivity::Secret)],
        [(name, value.as_os_str())],
    );
    assert!(!output.text().as_str().contains(SENTINEL));
    assert!(output.text().as_str().is_char_boundary(output.text().as_str().len()));

    let inspected = Redactor::standard()
        .inspect_process(
            program.as_os_str(),
            [ArgvItem::plain(value.as_os_str())],
            [(name, value.as_os_str())],
        )
        .expect("process input is within default limits");
    assert_eq!(inspected.max_sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(inspected.usage().output_bytes(), 0);

    let maximum_input = program.as_os_str().as_encoded_bytes().len()
        + value.as_os_str().as_encoded_bytes().len()
        + name.as_encoded_bytes().len()
        + value.as_os_str().as_encoded_bytes().len()
        - 1;
    let process_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(maximum_input);
        })
        .expect("valid process input limit")
        .build()
        .expect("valid policy");
    let bounded_process = Redactor::new(process_policy).redact_process(
        program.as_os_str(),
        [ArgvItem::plain(value.as_os_str())],
        [(name, value.as_os_str())],
    );
    assert!(bounded_process.summary().usage().inspected_input_bytes() <= maximum_input);
    assert!(
        bounded_process
            .summary()
            .reasons()
            .contains(RedactionReason::InputLimitReached)
    );
}

#[test]
fn test_windows_os_string_input_budget_uses_encoded_byte_length() {
    let value = wide(&[0xD83D, 0xDE00]);
    let input_bytes = value.as_os_str().as_encoded_bytes().len();
    let exact_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(input_bytes);
        })
        .expect("valid exact input limit")
        .build()
        .expect("valid policy");
    let exact = Redactor::new(exact_policy).redact_argv([ArgvItem::plain(&value)]);
    assert_eq!(exact.summary().usage().inspected_input_bytes(), input_bytes);
    assert_eq!(exact.summary().completion(), RedactionCompletion::Complete);

    let short_policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(input_bytes - 1);
        })
        .expect("valid short input limit")
        .build()
        .expect("valid policy");
    let short = Redactor::new(short_policy).redact_argv([ArgvItem::plain(&value)]);
    assert!(short.summary().usage().inspected_input_bytes() <= input_bytes - 1);
    assert!(short.summary().reasons().contains(RedactionReason::InputLimitReached));
}
