// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use std::fmt::Write;

use http::{
    HeaderMap,
    HeaderValue,
};
use libfuzzer_sys::fuzz_target;
use qubit_redact::http::{
    DiagnosticBudget,
    HttpRedactionPolicy,
    HttpRedactor,
};
use url::Url;

const FUZZ_SECRET: &str = "qubit-fuzz-secret-7f54a19c";
const DIAGNOSTIC_INPUT_LIMIT: usize = 128;
const DIAGNOSTIC_OUTPUT_LIMIT: usize = 64;
/// Maximum fuzzer input processed before constructing diagnostic strings.
///
/// The bound matches the CI smoke limit and prevents the URL construction from
/// allocating directly from an arbitrarily large UTF-8 input.
const FUZZ_INPUT_LIMIT: usize = 4096;

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

/// Verifies every diagnostic adapter respects one deliberately small budget.
///
/// # Parameters
///
/// * `data` - Fuzzer-provided bytes used to construct bounded diagnostic
///   inputs.
fn assert_diagnostic_outputs_are_bounded(data: &[u8]) {
    let budget =
        DiagnosticBudget::new(DIAGNOSTIC_INPUT_LIMIT, DIAGNOSTIC_OUTPUT_LIMIT)
            .expect("the fixed fuzz diagnostic budget is valid");
    let policy = HttpRedactionPolicy::builder()
        .diagnostic_budget(budget)
        .build()
        .expect("the fixed fuzz HTTP policy is valid");
    let redactor = HttpRedactor::new(policy);
    let noise = hexadecimal_prefix(data);
    let form = format!("note={noise}&password={FUZZ_SECRET}");
    let url_text = format!("https://example.test/?{form}");
    let parsed_url =
        Url::parse(&url_text).expect("the generated fuzz URL is valid");
    let text = format!("request failed near {url_text}");
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-fuzz-input",
        HeaderValue::from_str(&noise)
            .expect("hexadecimal fuzz text is a valid header value"),
    );

    let outputs = [
        redactor.redact_form(&form).to_string(),
        redactor.redact_url_str(&url_text).to_string(),
        redactor.redact_url(&parsed_url).to_string(),
        redactor.redact_urls_in_text(&text).to_string(),
        redactor.redact_headers(&headers).to_string(),
    ];
    for output in outputs {
        assert!(output.len() <= DIAGNOSTIC_OUTPUT_LIMIT);
        assert!(std::str::from_utf8(output.as_bytes()).is_ok());
    }
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(FUZZ_INPUT_LIMIT)];
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
    assert_diagnostic_outputs_are_bounded(data);
});
