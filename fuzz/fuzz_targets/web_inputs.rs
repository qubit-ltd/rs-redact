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
use qubit_redact::http::HttpRedactor;

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
    let redactor = HttpRedactor::default();
    let redacted_form = redactor.redact_form(&form);
    assert!(!redacted_form.as_ref().contains(FUZZ_SECRET));

    let url = format!("https://example.test/?{form}");
    let redacted_url = redactor.redact_url_str(&url);
    assert!(!redacted_url.as_ref().contains(FUZZ_SECRET));
}

/// Verifies malformed percent escapes fail closed in form and URL adapters.
fn assert_malformed_structured_secret_is_redacted() {
    for suffix in ["%", "%FF"] {
        let form = format!("password={FUZZ_SECRET}&noise={suffix}");
        let redactor = HttpRedactor::default();
        let redacted_form = redactor.redact_form(&form);
        assert!(!redacted_form.as_ref().contains(FUZZ_SECRET));

        let url = format!("https://example.test/?{form}");
        let redacted_url = redactor.redact_url_str(&url);
        assert!(!redacted_url.as_ref().contains(FUZZ_SECRET));
    }
}

fuzz_target!(|data: &[u8]| {
    let redactor = HttpRedactor::default();
    if let Ok(text) = std::str::from_utf8(data) {
        let first_form = redactor.redact_form(text);
        let second_form = redactor.redact_form(text);
        assert_eq!(first_form, second_form);

        let url = format!("https://example.test/?{text}");
        let first_url = redactor.redact_url_str(&url);
        let second_url = redactor.redact_url_str(&url);
        assert_eq!(first_url, second_url);
    }
    assert_structured_secret_is_redacted(data);
    assert_malformed_structured_secret_is_redacted();
});
