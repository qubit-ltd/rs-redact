// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
use std::ffi::OsStr;
use std::ffi::OsString;
#[cfg(not(test))]
use std::fmt::Write;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;

#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
#[cfg(not(test))]
use qubit_redact::Redactor;
#[cfg(not(test))]
use qubit_redact::Sensitivity;
#[cfg(not(test))]
use qubit_redact::formats::argv::ArgvItem;

#[cfg(not(test))]
const FUZZ_SECRET: &str = "qubit-fuzz-secret-7f54a19c";

/// Decodes bounded native argv tokens from length-prefixed fuzzer bytes.
///
/// # Parameters
///
/// * `data` - Fuzzer-provided bytes used only as non-sensitive noise.
///
/// # Returns
///
/// Up to 32 tokens, each containing at most 128 input bytes.
#[must_use]
fn raw_tokens(data: &[u8]) -> Vec<OsString> {
    let data = &data[..data.len().min(4096)];
    let mut tokens = Vec::with_capacity(data.len().min(32));
    let mut offset = 0;
    while offset < data.len() && tokens.len() < 32 {
        let length = usize::from(data[offset]) % 129;
        offset += 1;
        let end = offset.saturating_add(length).min(data.len());
        let bytes = &data[offset..end];
        #[cfg(unix)]
        let token = OsString::from_vec(bytes.to_vec());
        #[cfg(windows)]
        let token = {
            let units = bytes
                .chunks(2)
                .map(|pair| u16::from_le_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
            OsString::from_wide(&units.collect::<Vec<_>>())
        };
        #[cfg(not(any(unix, windows)))]
        let token = OsString::from(String::from_utf8_lossy(bytes).into_owned());
        tokens.push(token);
        offset = end;
    }
    tokens
}

/// Builds harmless positional noise for deterministic semantic cases.
///
/// # Parameters
///
/// * `data` - Fuzzer-provided bytes used only as non-sensitive noise.
///
/// # Returns
///
/// Up to 16 hexadecimal tokens that cannot alter option-parser state.
#[must_use]
#[cfg(not(test))]
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

/// Exercises arbitrary native argv tokens through the option heuristic.
#[cfg(not(test))]
fn assert_random_argv(data: &[u8]) {
    let tokens = raw_tokens(data);
    let render = || {
        let items = tokens.iter().map(|value| ArgvItem::plain(value.as_ref()));
        redact_argv_heuristically(items)
    };
    let first = render();
    let second = render();
    assert_eq!(first, second);
    assert!(first.len() <= 16 * 1024);
    assert!(first.is_char_boundary(first.len()));
    assert!(!first.chars().any(char::is_control));

    // Keep this assertion's prefix small enough that output truncation cannot
    // hide the final explicit redaction marker; the full input is checked
    // above for deterministic bounded output.
    let mut items: Vec<_> = tokens
        .iter()
        .take(1)
        .map(|value| ArgvItem::plain(value.as_ref()))
        .collect();
    items.push(ArgvItem::sensitive(OsStr::new(FUZZ_SECRET), Sensitivity::Secret));
    let redacted = redact_argv_heuristically(items);
    assert!(redacted.ends_with(r#""<redacted>"]"#));
}

/// Verifies one semantically sensitive argv shape removes the fixed secret.
///
/// # Parameters
///
/// * `selector` - Chooses a supported sensitive argv representation.
/// * `data` - Fuzzer-provided bytes used as harmless positional noise.
#[cfg(not(test))]
fn assert_sensitive_argv_is_redacted(selector: u8, data: &[u8]) {
    let mut argv = vec!["client".to_string()];
    argv.extend(noise_tokens(data));
    match selector % 7 {
        0 => argv.extend(["--password".to_string(), FUZZ_SECRET.to_string()]),
        1 => argv.push(format!("--password={FUZZ_SECRET}")),
        2 => argv.push(format!("PASSWORD={FUZZ_SECRET}")),
        3 => argv.extend(["--token".to_string(), "--password".to_string(), FUZZ_SECRET.to_string()]),
        4 => argv.extend(["-".to_string(), "--password".to_string(), FUZZ_SECRET.to_string()]),
        5 => argv.extend(["---".to_string(), "--password".to_string(), FUZZ_SECRET.to_string()]),
        _ => argv.extend(["--access-key-id".to_string(), format!("--password={FUZZ_SECRET}")]),
    }
    let items = argv.iter().map(|value| ArgvItem::plain(value.as_ref()));
    let first = redact_argv_heuristically(items);
    let items = argv.iter().map(|value| ArgvItem::plain(value.as_ref()));
    let second = redact_argv_heuristically(items);
    assert_eq!(first, second);
    assert!(!first.contains(FUZZ_SECRET));
    if selector % 7 == 6 {
        assert!(first.ends_with(r#""<redacted>"]"#));
    }
}

/// Verifies environment redaction removes the fixed secret.
#[cfg(not(test))]
fn assert_sensitive_environment_is_redacted() {
    let redactor = Redactor::standard();
    let first = redactor.redact_env("PASSWORD", FUZZ_SECRET).text().as_str().to_owned();
    let second = redactor.redact_env("PASSWORD", FUZZ_SECRET).text().as_str().to_owned();
    assert_eq!(first, second);
    assert!(!first.contains(FUZZ_SECRET));
}

/// Verifies Unix non-UTF-8 environment values fail closed.
///
/// # Parameters
///
/// * `data` - Fuzzer-provided bytes appended as bounded non-secret noise.
#[cfg(unix)]
#[cfg(not(test))]
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
#[cfg(not(test))]
fn assert_non_utf8_argv_is_redacted() {
    let option = OsString::from_vec(b"--password\xff".to_vec());
    let argv = [OsString::from("client"), option, OsString::from(FUZZ_SECRET)];
    let items = argv.iter().map(|value| ArgvItem::plain(value.as_ref()));
    let redacted = redact_argv_heuristically(items);
    assert!(!redacted.contains(FUZZ_SECRET));
}

/// Redacts argv with option-name heuristics through one complete transaction.
#[cfg(not(test))]
fn redact_argv_heuristically<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = ArgvItem<'a>>,
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
#[cfg(not(test))]
fn redact_os_environment_pair(name: &std::ffi::OsStr, value: &std::ffi::OsStr) -> String {
    let output = Redactor::standard()
        .text_composer()
        .env(|env| {
            env.os_pairs([(name, value)]);
        })
        .finish();
    output.text().as_str().to_owned()
}

#[cfg(not(test))]
fuzz_target!(|data: &[u8]| {
    assert_random_argv(data);
    let (selector, noise) = data.split_first().map_or((0, data), |(value, rest)| (*value, rest));
    assert_sensitive_argv_is_redacted(selector, noise);
    assert_sensitive_environment_is_redacted();
    #[cfg(unix)]
    assert_non_utf8_environment_is_redacted(noise);
    #[cfg(unix)]
    assert_non_utf8_argv_is_redacted();

    let boundary_argv = ["client", "--", "--password", FUZZ_SECRET];
    let items = boundary_argv.iter().map(|value| ArgvItem::plain(value.as_ref()));
    let first = redact_argv_heuristically(items);
    let items = boundary_argv.iter().map(|value| ArgvItem::plain(value.as_ref()));
    let second = redact_argv_heuristically(items);
    assert_eq!(first, second);
    assert!(!first.contains(FUZZ_SECRET));

    let inline_secret = format!("--password={FUZZ_SECRET}");
    let boundary_inline_argv = ["client", "--", inline_secret.as_str()];
    let items = boundary_inline_argv.iter().map(|value| ArgvItem::plain(value.as_ref()));
    let redacted = redact_argv_heuristically(items);
    assert!(!redacted.contains(FUZZ_SECRET));
});

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::raw_tokens;

    #[cfg(not(windows))]
    #[test]
    fn test_rr2_raw_argv_preserves_option_syntax() {
        let data = [10, b'-', b'-', b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', 1, b'='];
        assert_eq!(raw_tokens(&data), [OsString::from("--password"), OsString::from("=")]);
    }

    #[cfg(windows)]
    #[test]
    fn test_rr2_raw_argv_windows_utf16_syntax() {
        let bytes: Vec<u8> = "--password".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut data = vec![bytes.len() as u8];
        data.extend(bytes);
        data.extend([2, b'=', 0]);
        assert_eq!(raw_tokens(&data), [OsString::from("--password"), OsString::from("=")]);
    }

    #[cfg(unix)]
    #[test]
    fn test_rr2_raw_argv_preserves_non_utf8_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let tokens = raw_tokens(&[2, 0xff, b'=']);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].as_bytes(), [0xff, b'=']);
    }

    #[test]
    fn test_rr2_raw_argv_limits_input_and_tokens() {
        assert!(raw_tokens(&[]).is_empty());
        assert_eq!(raw_tokens(&[128, b'x']).len(), 1);
        assert!(raw_tokens(&[128; 4097]).len() <= 32);
        assert!(raw_tokens(&vec![0; 4097]).len() <= 32);
    }
}
