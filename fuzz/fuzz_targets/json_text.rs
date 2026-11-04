// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg_attr(not(test), no_main)]

use std::fmt::Write;

#[path = "support/log_safety.rs"]
mod log_safety;

#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionTextOutput;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

const FUZZ_SECRET: &str = "json-fuzz-secret-91c2e637";
const VISIBLE: &str = "rra001-visible";
const PASSWORD_TOKEN: &str = "\"password\"";
const ESCAPED_PASSWORD_TOKEN: &str = "\"pass\\u0077ord\"";

/// Encodes arbitrary bytes as a bounded JSON string value.
#[must_use]
fn encoded_noise(input: &[u8]) -> String {
    let mut encoded = String::with_capacity(input.len().saturating_mul(2));
    for byte in input.iter().take(128) {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn assert_output_invariants(output: &RedactionTextOutput, max_output_bytes: usize) {
    assert_output_text_invariants(output.text().as_str(), max_output_bytes);
}

fn assert_output_text_invariants(text: &str, max_output_bytes: usize) {
    assert!(text.len() <= max_output_bytes);
    log_safety::assert_log_safe(text);
}

fn output_limited_redactor(max_output_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(max_output_bytes);
        })
        .expect("output budget is valid")
        .build()
        .expect("policy is valid");
    Redactor::new(policy)
}

fn generated_json(case: usize, key_case: usize, noise: &str) -> String {
    let key = match key_case % 3 {
        0 => "password",
        1 => "PASSWORD",
        _ => "password",
    };
    let value = serde_json::json!({
        "visible": VISIBLE,
        "noise": noise,
        key: FUZZ_SECRET,
    });
    let mut json = match case % 3 {
        0 => value.to_string(),
        1 => serde_json::json!({ "nested": value }).to_string(),
        _ => serde_json::json!([value]).to_string(),
    };
    if key_case % 3 == 2 {
        // Replace only the known serialized field-name token.
        json = json.replacen(PASSWORD_TOKEN, ESCAPED_PASSWORD_TOKEN, 1);
    }
    json
}

fn assert_valid_output(output: &RedactionTextOutput, case: usize, key_case: usize) {
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_output_invariants(output, Redactor::standard().policy().limits().max_output_bytes());
    assert_valid_text(output.text().as_str(), case, key_case);
}

fn assert_valid_text(text: &str, case: usize, key_case: usize) {
    let value: serde_json::Value = serde_json::from_str(text).expect("output must be valid JSON");
    let target = match case % 3 {
        0 => &value,
        1 => value.get("nested").expect("nested object must remain"),
        _ => value.get(0).expect("array element must remain"),
    };
    assert_eq!(target.get("visible").and_then(serde_json::Value::as_str), Some(VISIBLE));
    let password_key = if key_case % 3 == 1 { "PASSWORD" } else { "password" };
    assert_eq!(
        target.get(password_key).and_then(serde_json::Value::as_str),
        Some(Redactor::standard().policy().masking().mask_opaque(Sensitivity::Secret)),
    );
    assert!(!text.contains(FUZZ_SECRET));
}

fn exercise(input: &[u8]) {
    let input = &input[..input.len().min(4_096)];
    let arbitrary = String::from_utf8_lossy(input);
    let redactor = Redactor::standard();
    let max_output_bytes = redactor.policy().limits().max_output_bytes();

    let first = redactor.redact_json(&arbitrary);
    let second = redactor.redact_json(&arbitrary);
    assert_eq!(first, second);
    assert_output_invariants(&first, max_output_bytes);

    let case = input.first().copied().unwrap_or(0) as usize % 3;
    let key_case = input.get(1).copied().unwrap_or(0) as usize % 3;
    let sensitive = generated_json(case, key_case, &encoded_noise(input));
    let output = redactor.redact_json(&sensitive);
    assert_valid_output(&output, case, key_case);

    let pressure_budget = [0, 1, 4, 8, 16, 32, 128][input.get(2).copied().unwrap_or(0) as usize % 7];
    let pressure = output_limited_redactor(pressure_budget).redact_json(&sensitive);
    assert_output_invariants(&pressure, pressure_budget);
    assert!(!pressure.text().as_str().contains(FUZZ_SECRET));
}

#[cfg(not(test))]
fuzz_target!(|input: &[u8]| exercise(input));

#[cfg(test)]
mod tests {
    use std::panic::AssertUnwindSafe;
    use std::panic::catch_unwind;

    use super::ESCAPED_PASSWORD_TOKEN;
    use super::FUZZ_SECRET;
    use super::VISIBLE;
    use super::assert_output_invariants;
    use super::assert_valid_text;
    use super::exercise;
    use super::generated_json;
    use super::output_limited_redactor;

    #[test]
    fn generated_inputs_cover_shapes_and_key_spellings() {
        for case in 0..3 {
            for key_case in 0..3 {
                let json = generated_json(case, key_case, "00");
                let value: serde_json::Value = serde_json::from_str(&json).unwrap();
                let target = match case {
                    0 => &value,
                    1 => value.get("nested").unwrap(),
                    _ => value.get(0).unwrap(),
                };
                let password_key = if key_case == 1 { "PASSWORD" } else { "password" };
                let password = target.get(password_key).unwrap();
                assert_eq!(password, FUZZ_SECRET);
                assert_eq!(target.get("visible").unwrap(), VISIBLE);
                if key_case == 1 {
                    assert!(target.get("PASSWORD").is_some());
                }
                if key_case == 2 {
                    assert!(json.contains(ESCAPED_PASSWORD_TOKEN));
                }
                exercise(&[case as u8, key_case as u8]);
            }
        }
    }

    #[test]
    fn input_edges_and_pressure_budgets_complete_success_path() {
        for input in [&[][..], &[0; 64][..], &[255; 4_097][..]] {
            exercise(input);
        }
        for budget in [0, 1, 4, 8, 16, 32, 128] {
            let json = generated_json(0, 0, "00");
            let output = output_limited_redactor(budget).redact_json(&json);
            assert_output_invariants(&output, budget);
            assert!(!output.text().as_str().contains(FUZZ_SECRET));
        }
    }

    #[test]
    fn success_oracle_rejects_invalid_or_degraded_outputs() {
        let cases = [
            "",
            "<redacted>",
            "not json",
            "{}",
            r#"{"visible":"rra001-visible","password":"json-fuzz-secret-91c2e637"}"#,
            r#"{"password":"[secret]"}"#,
        ];
        for text in cases {
            assert!(catch_unwind(AssertUnwindSafe(|| assert_valid_text(text, 0, 0))).is_err());
        }
    }
}
