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

const FUZZ_SECRET: &str = "multipart-fuzz-secret-b08761d5";

/// Encodes arbitrary bytes as inert multipart text.
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
    let redactor = Redactor::standard();
    let max_output_bytes = redactor.policy().limits().max_output_bytes();
    let boundary = format!("qubit-fuzz-{}", encoded_noise(input.get(..16).unwrap_or(input)));
    let content_type = HeaderValue::from_str(&format!("multipart/form-data; boundary={boundary}"))
        .expect("hex-encoded boundary must be valid");

    let first = redactor.redact_http_body(BodyCapture::complete(input), Some(&content_type));
    let second = redactor.redact_http_body(BodyCapture::complete(input), Some(&content_type));
    assert_eq!(first, second);
    assert_output_invariants(&first, max_output_bytes);

    let noise = encoded_noise(input);
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"note\"\r\n\r\n\
         {noise}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"password\"\r\n\r\n\
         {FUZZ_SECRET}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"upload\"; filename=\"secret.txt\"\r\n\
         X-Fuzz-Part: {noise}\r\n\
         Content-Type: application/octet-stream\r\n\r\n\
         {FUZZ_SECRET}\r\n\
         --{boundary}--\r\n"
    );
    let output = redactor.redact_http_body(BodyCapture::complete(body.as_bytes()), Some(&content_type));
    assert_output_invariants(&output, max_output_bytes);
    assert!(!output.text().as_str().contains(FUZZ_SECRET));

    let retained = usize::from(input.first().copied().unwrap_or_default()) % body.len();
    let truncated = BodyCapture::prefix(body.as_bytes(), retained);
    let output = redactor.redact_http_body(truncated, Some(&content_type));
    assert_output_invariants(&output, max_output_bytes);
    assert!(!output.text().as_str().contains(FUZZ_SECRET));
});
