// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use std::fmt::Write;

use libfuzzer_sys::fuzz_target;
use qubit_sanitize::{
    FormUrlEncodedSanitizer,
    NameMatchMode,
    UrlSanitizer,
};

const FUZZ_SECRET: &str = "qubit-fuzz-secret-7f54a19c";

/// Encodes a bounded input prefix as lowercase hexadecimal text.
///
/// # Parameters
///
/// * `data` - Fuzzer-provided bytes used as structured non-secret noise.
///
/// # Returns
///
/// Hexadecimal text for at most the first 64 bytes.
#[must_use]
fn hexadecimal_prefix(data: &[u8]) -> String {
    let mut encoded = String::with_capacity(data.len().min(64) * 2);
    for byte in data.iter().take(64) {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

/// Verifies form and URL adapters remove a known query-value secret.
///
/// # Parameters
///
/// * `data` - Fuzzer-provided bytes used as non-secret structured noise.
fn assert_structured_secret_is_redacted(data: &[u8]) {
    let noise = hexadecimal_prefix(data);
    let form = format!("noise={noise}&password={FUZZ_SECRET}");
    let sanitized_form = FormUrlEncodedSanitizer::default()
        .sanitize_str(&form, NameMatchMode::ExactOrSuffix);
    assert!(!sanitized_form.contains(FUZZ_SECRET));

    let url = format!("https://example.test/?{form}");
    let sanitized_url = UrlSanitizer::default()
        .sanitize_url_str(&url, NameMatchMode::ExactOrSuffix)
        .expect("the constructed fuzz URL should parse");
    assert!(!sanitized_url.contains(FUZZ_SECRET));
}

fuzz_target!(|data: &[u8]| {
    let form_sanitizer = FormUrlEncodedSanitizer::default();
    let first_form =
        form_sanitizer.sanitize_bytes(data, NameMatchMode::ExactOrSuffix);
    let second_form =
        form_sanitizer.sanitize_bytes(data, NameMatchMode::ExactOrSuffix);
    assert_eq!(first_form, second_form);

    if let Ok(text) = std::str::from_utf8(data) {
        let url = format!("https://example.test/?{text}");
        let url_sanitizer = UrlSanitizer::default();
        let first_url =
            url_sanitizer.sanitize_url_str(&url, NameMatchMode::ExactOrSuffix);
        let second_url =
            url_sanitizer.sanitize_url_str(&url, NameMatchMode::ExactOrSuffix);
        assert_eq!(first_url, second_url);
    }
    assert_structured_secret_is_redacted(data);
});
