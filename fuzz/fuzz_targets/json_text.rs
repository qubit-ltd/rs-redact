// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use std::fmt::Write;

use libfuzzer_sys::fuzz_target;
use qubit_redact::RedactionTextOutput;
use qubit_redact::Redactor;

const FUZZ_SECRET: &str = "json-fuzz-secret-91c2e637";

/// Encodes arbitrary bytes as a bounded JSON string value.
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
    let arbitrary = String::from_utf8_lossy(input);
    let redactor = Redactor::standard();
    let max_output_bytes = redactor.policy().limits().max_output_bytes();

    let first = redactor.redact_json(&arbitrary);
    let second = redactor.redact_json(&arbitrary);
    assert_eq!(first, second);
    assert_output_invariants(&first, max_output_bytes);

    let sensitive = format!(r#"{{"noise":"{}","password":"{FUZZ_SECRET}"}}"#, encoded_noise(input));
    let output = redactor.redact_json(&sensitive);
    assert_output_invariants(&output, max_output_bytes);
    assert!(!output.text().as_str().contains(FUZZ_SECRET));
});
