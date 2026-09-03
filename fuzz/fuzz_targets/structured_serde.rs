// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![no_main]

use std::collections::BTreeMap;
use std::fmt::Write;

use libfuzzer_sys::fuzz_target;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::domain::internal::RedactedMapKeySerializeRef;

const FUZZ_SECRET: &str = "structured-serde-secret-6cb79f12";

/// Encodes arbitrary bytes into deterministic UTF-8 map keys.
#[must_use]
fn encoded_key(input: &[u8], index: usize) -> String {
    let mut key = format!("key-{index}-");
    for byte in input.iter().take(16) {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(1_024)];
    let requested_limit = usize::from(input.first().copied().unwrap_or_default() % 17);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(requested_limit);
        })
        .expect("bounded fuzz limits must be valid")
        .build()
        .expect("bounded fuzz policy must be valid");
    let mut values = input
        .chunks(16)
        .take(32)
        .enumerate()
        .map(|(index, chunk)| (encoded_key(chunk, index), String::from(FUZZ_SECRET)))
        .collect::<BTreeMap<_, _>>();
    values.insert(String::from("fixed-sensitive-key"), String::from(FUZZ_SECRET));

    let first = serde_json::to_value(RedactedMapKeySerializeRef::new(
        &values,
        &policy,
        Sensitivity::Secret,
        Some(Sensitivity::Secret),
    ))
    .map_err(|error| error.to_string());
    let second = serde_json::to_value(RedactedMapKeySerializeRef::new(
        &values,
        &policy,
        Sensitivity::Secret,
        Some(Sensitivity::Secret),
    ))
    .map_err(|error| error.to_string());

    assert_eq!(first, second);
    if let Ok(output) = first {
        let rendered = output.to_string();
        assert!(!rendered.contains("fixed-sensitive-key"));
        assert!(!rendered.contains(FUZZ_SECRET));
    }
});
