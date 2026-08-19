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
use qubit_redact::Redactor;

const FUZZ_SECRET: &str = "qubit-fuzz-secret-7f54a19c";

/// Encodes fuzzer bytes as an inert query value.
///
/// The direct URL and URI adapters classify values from their field names.
/// Encoding the arbitrary bytes keeps the constructed URL valid while the
/// fixed secret is placed in a known-sensitive `password` field.
#[must_use]
fn query_noise(input: &[u8]) -> String {
    let mut encoded = String::with_capacity(input.len().saturating_mul(2));
    for byte in input {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fuzz_target!(|input: &[u8]| {
    let text = String::from_utf8_lossy(input);
    let redactor = Redactor::standard();

    // Arbitrary direct inputs may be syntactically valid opaque URLs. Their
    // unclassified path text is intentionally preserved by the standard
    // policy, so this check is for deterministic, panic-free processing only.
    assert_eq!(redactor.redact_http_url(&text), redactor.redact_http_url(&text));
    assert_eq!(redactor.redact_uri(&text), redactor.redact_uri(&text));

    let sensitive_url = format!(
        "https://fuzz.example/?noise={}&password={FUZZ_SECRET}",
        query_noise(input)
    );
    let url = redactor.redact_http_url(&sensitive_url);
    assert!(!url.text().as_str().contains(FUZZ_SECRET));
    let uri = redactor.redact_uri(&sensitive_url);
    assert!(!uri.text().as_str().contains(FUZZ_SECRET));
});
