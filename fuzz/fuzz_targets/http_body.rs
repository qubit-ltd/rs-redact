// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use std::fmt::Write;

use http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use qubit_redact::RedactionTextOutput;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

const FUZZ_SECRET: &str = "http-body-fuzz-secret-427b93e1";

/// Encodes arbitrary bytes for use in valid structured bodies.
#[must_use]
fn encoded_noise(input: &[u8]) -> String {
    let mut encoded = String::with_capacity(input.len().saturating_mul(2));
    for byte in input.iter().take(2_048) {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Checks the publication invariants shared by every fuzzed operation.
fn assert_output_invariants(output: &RedactionTextOutput, max_output_bytes: usize) {
    let text = output.text().as_str();
    assert!(text.len() <= max_output_bytes);
    assert!(!text.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
            )
    }));
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(4_096)];
    let selector = input.first().copied().unwrap_or_default();
    let content_types = [
        "application/json",
        "application/x-ndjson",
        "application/x-www-form-urlencoded",
        "text/plain; charset=utf-8",
        "application/octet-stream",
    ];
    let content_type = format!(
        "{}; fuzz={}",
        content_types[usize::from(selector) % content_types.len()],
        encoded_noise(input.get(1..17).unwrap_or_default())
    );
    let content_type = HeaderValue::from_str(&content_type).expect("hex-encoded content type must be valid");
    let redactor = Redactor::standard();
    let max_output_bytes = redactor.policy().limits().max_output_bytes();

    let first = redactor.redact_http_body(BodyCapture::complete(input), Some(&content_type));
    let second = redactor.redact_http_body(BodyCapture::complete(input), Some(&content_type));
    assert_eq!(first, second);
    assert_output_invariants(&first, max_output_bytes);

    let noise = encoded_noise(input);
    let cases = [
        (
            format!(r#"{{"noise":"{noise}","password":"{FUZZ_SECRET}"}}"#),
            HeaderValue::from_static("application/json"),
        ),
        (
            format!("noise={noise}&password={FUZZ_SECRET}"),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ),
        (
            format!(r#"{{"noise":"{noise}"}}\n{{"password":"{FUZZ_SECRET}"}}"#),
            HeaderValue::from_static("application/x-ndjson"),
        ),
    ];
    for (body, content_type) in cases {
        let output = redactor.redact_http_body(BodyCapture::complete(body.as_bytes()), Some(&content_type));
        assert_output_invariants(&output, max_output_bytes);
        assert!(!output.text().as_str().contains(FUZZ_SECRET));
    }
});
