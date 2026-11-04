// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg_attr(not(test), no_main)]

use std::collections::BTreeMap;
use std::fmt::Write;

#[cfg(not(test))]
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

fn exercise(input: &[u8]) {
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

    // A standard policy has sufficient budget for this bounded map. Keep this
    // success path independent of the fuzzed collection limit above.
    let standard = RedactionPolicy::standard();
    // Sensitive keys all receive the same redacted spelling, and this
    // serializer rejects those collisions. Use one bounded entry so the
    // mandatory success oracle tests successful serialization independently.
    let standard_values = BTreeMap::from([(String::from("fixed-sensitive-key"), String::from(FUZZ_SECRET))]);
    let serialize_standard = || {
        serde_json::to_value(RedactedMapKeySerializeRef::new(
            &standard_values,
            &standard,
            Sensitivity::Secret,
            Some(Sensitivity::Secret),
        ))
        .map_err(|error| error.to_string())
    };
    let standard_first = serialize_standard();
    let standard_second = serialize_standard();
    assert_eq!(standard_first, standard_second);
    assert_masked_success(standard_first);

    let public_values = BTreeMap::from([(String::from("fixed-sensitive-key"), String::from("rra001-visible"))]);
    let public_result = serde_json::to_value(RedactedMapKeySerializeRef::new(
        &public_values,
        &standard,
        Sensitivity::Secret,
        None,
    ))
    .map_err(|error| error.to_string());
    assert_visible_success(public_result);
}

fn assert_masked_success(result: Result<serde_json::Value, String>) {
    let output = result.expect("standard-budget serialization must succeed");
    let object = output
        .as_object()
        .expect("standard-budget output must be a JSON object");
    assert!(!object.is_empty(), "standard-budget object must not be empty");
    let rendered = output.to_string();
    assert!(!rendered.contains("fixed-sensitive-key"));
    assert!(!rendered.contains(FUZZ_SECRET));
}

fn assert_visible_success(result: Result<serde_json::Value, String>) {
    let output = result.expect("single-entry public serialization must succeed");
    let object = output
        .as_object()
        .expect("single-entry public output must be a JSON object");
    assert_eq!(object.len(), 1);
    assert!(!object.contains_key("fixed-sensitive-key"));
    assert_eq!(object.values().next(), Some(&serde_json::json!("rra001-visible")));
}

#[cfg(not(test))]
fuzz_target!(|input: &[u8]| exercise(input));

#[cfg(test)]
mod tests {
    use std::panic::AssertUnwindSafe;
    use std::panic::catch_unwind;

    use super::assert_masked_success;
    use super::assert_visible_success;
    use super::exercise;

    fn assert_rejected(assertion: impl FnOnce()) {
        assert!(catch_unwind(AssertUnwindSafe(assertion)).is_err());
    }

    #[test]
    fn exercise_accepts_empty_maximum_and_all_selectors() {
        exercise(&[]);
        exercise(&vec![0; 1_024]);
        exercise(&vec![u8::MAX; 1_024]);
        for selector in 0..17 {
            let mut input = vec![0; 1_024];
            input[0] = selector;
            exercise(&input);
        }
    }

    #[test]
    fn masked_success_oracle_rejects_failures_and_leaks() {
        assert_rejected(|| assert_masked_success(Err(String::from("synthetic failure"))));
        assert_rejected(|| assert_masked_success(Ok(serde_json::json!({}))));
        assert_rejected(|| assert_masked_success(Ok(serde_json::json!("scalar"))));
        assert_rejected(|| {
            assert_masked_success(Ok(serde_json::json!({
                "fixed-sensitive-key": "masked",
                "other": "safe"
            })))
        });
        assert_rejected(|| assert_masked_success(Ok(serde_json::json!({"other": super::FUZZ_SECRET}))));
    }

    #[test]
    fn visible_success_oracle_rejects_failures_and_value_loss() {
        assert_rejected(|| assert_visible_success(Err(String::from("synthetic failure"))));
        assert_rejected(|| assert_visible_success(Ok(serde_json::json!({}))));
        assert_rejected(|| assert_visible_success(Ok(serde_json::json!("scalar"))));
        assert_rejected(|| assert_visible_success(Ok(serde_json::json!({"masked-key": "wrong-value"}))));
        assert_rejected(|| {
            assert_visible_success(Ok(serde_json::json!({
                "fixed-sensitive-key": "rra001-visible"
            })))
        });
    }
}
