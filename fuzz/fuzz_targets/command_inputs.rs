// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

#[cfg(unix)]
use std::ffi::OsString;
use std::fmt::Write;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

use libfuzzer_sys::fuzz_target;
use qubit_redact::Redactor;
use qubit_redact::formats::argv::ArgvItem;

const FUZZ_SECRET: &str = "qubit-fuzz-secret-7f54a19c";

/// Builds bounded ordinary argv tokens from fuzzer bytes.
///
/// # Parameters
///
/// * `data` - Fuzzer-provided bytes used only as non-sensitive noise.
///
/// # Returns
///
/// Up to 16 hexadecimal tokens that cannot alter option-parser state.
#[must_use]
fn noise_tokens(data: &[u8]) -> Vec<String> {
    data.chunks(4)
        .take(16)
        .map(|chunk| {
            let mut token = String::new();
            for byte in chunk {
                let _ = write!(&mut token, "{byte:02x}");
            }
            token
        })
        .collect()
}

/// Verifies one semantically sensitive argv shape removes the fixed secret.
///
/// # Parameters
///
/// * `selector` - Chooses a supported sensitive argv representation.
/// * `data` - Fuzzer-provided bytes used as harmless positional noise.
fn assert_sensitive_argv_is_redacted(selector: u8, data: &[u8]) {
    let mut argv = vec!["client".to_string()];
    argv.extend(noise_tokens(data));
    match selector % 6 {
        0 => argv.extend(["--password".to_string(), FUZZ_SECRET.to_string()]),
        1 => argv.push(format!("--password={FUZZ_SECRET}")),
        2 => argv.push(format!("PASSWORD={FUZZ_SECRET}")),
        3 => argv.extend([
            "--token".to_string(),
            "--password".to_string(),
            FUZZ_SECRET.to_string(),
        ]),
        4 => argv.extend([
            "-".to_string(),
            "--password".to_string(),
            FUZZ_SECRET.to_string(),
        ]),
        _ => argv.extend([
            "---".to_string(),
            "--password".to_string(),
            FUZZ_SECRET.to_string(),
        ]),
    }
    let items = argv.iter().map(|value| ArgvItem::plain(value.as_ref()));
    let first = redact_argv_heuristically(items);
    let items = argv.iter().map(|value| ArgvItem::plain(value.as_ref()));
    let second = redact_argv_heuristically(items);
    assert_eq!(first, second);
    assert!(!first.contains(FUZZ_SECRET));
}

/// Verifies environment redaction removes the fixed secret.
fn assert_sensitive_environment_is_redacted() {
    let redactor = Redactor::standard();
    let first = redactor
        .redact_env("PASSWORD", FUZZ_SECRET)
        .text()
        .as_str()
        .to_owned();
    let second = redactor
        .redact_env("PASSWORD", FUZZ_SECRET)
        .text()
        .as_str()
        .to_owned();
    assert_eq!(first, second);
    assert!(!first.contains(FUZZ_SECRET));
}

/// Verifies Unix non-UTF-8 environment values fail closed.
///
/// # Parameters
///
/// * `data` - Fuzzer-provided bytes appended as bounded non-secret noise.
#[cfg(unix)]
fn assert_non_utf8_environment_is_redacted(data: &[u8]) {
    let mut value_bytes = vec![0xff];
    value_bytes.extend_from_slice(FUZZ_SECRET.as_bytes());
    value_bytes.extend_from_slice(&data[..data.len().min(16)]);
    let value = OsString::from_vec(value_bytes);
    let redacted = redact_os_environment_pair(std::ffi::OsStr::new("PASSWORD"), &value);
    assert!(!redacted.contains(FUZZ_SECRET));

    let key = OsString::from_vec(b"PASS\xffWORD".to_vec());
    let value = OsString::from(FUZZ_SECRET);
    let redacted = redact_os_environment_pair(&key, &value);
    assert!(!redacted.contains(FUZZ_SECRET));
}

/// Verifies Unix non-UTF-8 argv tokens fail closed across parser state.
#[cfg(unix)]
fn assert_non_utf8_argv_is_redacted() {
    let option = OsString::from_vec(b"--password\xff".to_vec());
    let argv = [
        OsString::from("client"),
        option,
        OsString::from(FUZZ_SECRET),
    ];
    let items = argv.iter().map(|value| ArgvItem::plain(value.as_ref()));
    let redacted = redact_argv_heuristically(items);
    assert!(!redacted.contains(FUZZ_SECRET));
}

/// Redacts argv with option-name heuristics through one complete transaction.
fn redact_argv_heuristically<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = ArgvItem<'a>>,
    I::IntoIter: ExactSizeIterator,
{
    let output = Redactor::standard()
        .text_composer()
        .argv(|argv| {
            argv.heuristic_items(items);
        })
        .finish();
    output.text().as_str().to_owned()
}

/// Redacts a possibly non-UTF-8 environment assignment through the shared
/// session adapter.
#[cfg(unix)]
fn redact_os_environment_pair(name: &std::ffi::OsStr, value: &std::ffi::OsStr) -> String {
    let output = Redactor::standard()
        .text_composer()
        .env(|env| {
            env.os_pairs([(name, value)]);
        })
        .finish();
    output.text().as_str().to_owned()
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, noise)) = data.split_first() else {
        return;
    };
    assert_sensitive_argv_is_redacted(selector, noise);
    assert_sensitive_environment_is_redacted();
    #[cfg(unix)]
    assert_non_utf8_environment_is_redacted(noise);
    #[cfg(unix)]
    assert_non_utf8_argv_is_redacted();

    let boundary_argv = ["client", "--", "--password", FUZZ_SECRET];
    let items = boundary_argv
        .iter()
        .map(|value| ArgvItem::plain(value.as_ref()));
    let first = redact_argv_heuristically(items);
    let items = boundary_argv
        .iter()
        .map(|value| ArgvItem::plain(value.as_ref()));
    let second = redact_argv_heuristically(items);
    assert_eq!(first, second);
    assert!(!first.contains(FUZZ_SECRET));

    let inline_secret = format!("--password={FUZZ_SECRET}");
    let boundary_inline_argv = ["client", "--", inline_secret.as_str()];
    let items = boundary_inline_argv
        .iter()
        .map(|value| ArgvItem::plain(value.as_ref()));
    let redacted = redact_argv_heuristically(items);
    assert!(!redacted.contains(FUZZ_SECRET));
});
