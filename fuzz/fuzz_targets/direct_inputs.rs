// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg_attr(not(test), no_main)]

#[path = "support/log_safety.rs"]
mod log_safety;

#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionTextOutput;
use qubit_redact::Redactor;

const FUZZ_SECRET: &str = "qubit-fuzz-secret-7f54a19c";
const VISIBLE_SENTINEL: &str = "rr001-visible";
const OUTPUT_BUDGETS: &[usize] = &[0, 1, 4, 8, 9, 10, 16, 32, 128, 4096];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Entry {
    Http,
    Uri,
    Both,
}

#[derive(Debug)]
struct GeneratedCase {
    input: String,
    entry: Entry,
    contains_known_secret: bool,
    preserves_visible_sentinel: bool,
}

fn assert_output_invariants(output: &RedactionTextOutput, max_output_bytes: usize) {
    assert_text_invariants(output.text().as_str(), max_output_bytes);
}

fn assert_text_invariants(text: &str, max_output_bytes: usize) {
    assert!(text.len() <= max_output_bytes, "output exceeded byte budget");
    log_safety::assert_log_safe(text);
}

fn assert_secret_redacted(text: &str) {
    assert!(!text.contains(FUZZ_SECRET), "known secret was published");
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

fn bounded_noise(input: &[u8]) -> String {
    let mut result = String::with_capacity(input.len().min(128) * 2);
    for byte in input.iter().take(128) {
        use std::fmt::Write;
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

fn encode_layers(value: &str, depth: usize) -> String {
    let mut encoded = value.to_owned();
    for _ in 0..depth {
        encoded = url::form_urlencoded::byte_serialize(encoded.as_bytes()).collect();
    }
    encoded
}

fn generated_case(case: usize, budget_index: usize, depth: usize, noise: &str) -> GeneratedCase {
    let password_key = ["password", "pass%77ord", "%70assword"][budget_index % 3];
    let visible = format!("{VISIBLE_SENTINEL}{noise}");
    let (input, entry, preserves_visible_sentinel) = match case % 6 {
        0 => (
            format!("https://fuzz.example/?{password_key}={FUZZ_SECRET}&visible={visible}"),
            Entry::Both,
            true,
        ),
        1 => (
            format!("https://user:{FUZZ_SECRET}@fuzz.example/?visible={visible}"),
            Entry::Both,
            true,
        ),
        2 => {
            let repeated_passwords = 2 + budget_index % 3;
            let mut fields = vec![format!("visible={visible}"), format!("ordinary={noise}")];
            fields.splice(
                budget_index % (fields.len() + 1)..budget_index % (fields.len() + 1),
                std::iter::repeat_n(format!("password={FUZZ_SECRET}"), repeated_passwords),
            );
            (format!("https://fuzz.example/?{}", fields.join("&")), Entry::Both, true)
        }
        3 => {
            let inner = format!("https://inner.example/?password={FUZZ_SECRET}");
            let encoded = encode_layers(&inner, depth.clamp(1, 9));
            (
                format!("https://outer.example/?visible={visible}&next={encoded}"),
                Entry::Http,
                true,
            )
        }
        4 => (
            format!(
                "https://fuzz.example/?visible={visible}&password=https%3A%2F%2Finner.example%2F%3Fpassword%3D{FUZZ_SECRET}"
            ),
            Entry::Uri,
            true,
        ),
        _ => (
            format!("https://fuzz.example/?password=%{FUZZ_SECRET}%GG&visible={visible}%FF&ordinary=%GG"),
            Entry::Both,
            false,
        ),
    };
    GeneratedCase {
        input,
        entry,
        contains_known_secret: true,
        preserves_visible_sentinel,
    }
}

fn check_direct_output(redactor: &Redactor, output: &RedactionTextOutput, contains_secret: bool) {
    assert_output_invariants(output, redactor.policy().limits().max_output_bytes());
    if contains_secret {
        assert_secret_redacted(output.text().as_str());
    }
}

fn exercise(input: &[u8]) {
    // Clamp before UTF-8 conversion or any input-sized allocation.
    let input = &input[..input.len().min(4_096)];
    let raw = String::from_utf8_lossy(input);
    let standard = Redactor::standard();

    // Arbitrary direct text can legitimately remain visible in ordinary path
    // positions, so these checks cover determinism, size, and log safety only.
    let first_http = standard.redact_http_url(&raw);
    let second_http = standard.redact_http_url(&raw);
    assert_eq!(first_http, second_http);
    check_direct_output(&standard, &first_http, false);
    let first_uri = standard.redact_uri(&raw);
    let second_uri = standard.redact_uri(&raw);
    assert_eq!(first_uri, second_uri);
    check_direct_output(&standard, &first_uri, false);

    let case_index = usize::from(input.first().copied().unwrap_or_default()) % 6;
    let budget_index = usize::from(input.get(1).copied().unwrap_or_default()) % OUTPUT_BUDGETS.len();
    let depth = usize::from(input.get(2).copied().unwrap_or_default()) % 9 + 1;
    let noise = bounded_noise(input.get(3..).unwrap_or_default());
    let generated = generated_case(case_index, budget_index, depth, &noise);
    let redactor = output_limited_redactor(OUTPUT_BUDGETS[budget_index]);

    for entry in match generated.entry {
        Entry::Http => [Some(Entry::Http), None],
        Entry::Uri => [Some(Entry::Uri), None],
        Entry::Both => [Some(Entry::Http), Some(Entry::Uri)],
    }
    .into_iter()
    .flatten()
    {
        let output = match entry {
            Entry::Http => redactor.redact_http_url(&generated.input),
            Entry::Uri => redactor.redact_uri(&generated.input),
            Entry::Both => unreachable!("Both is expanded before dispatch"),
        };
        check_direct_output(&redactor, &output, generated.contains_known_secret);
        if generated.preserves_visible_sentinel && OUTPUT_BUDGETS[budget_index] == 4_096 {
            assert_eq!(
                output.summary().completion(),
                RedactionCompletion::Complete,
                "case {case_index} did not complete with a sufficient output budget"
            );
            assert!(
                output.text().as_str().contains(VISIBLE_SENTINEL),
                "case {case_index} lost visible content with a sufficient output budget"
            );
        }
    }
}

#[cfg(not(test))]
fuzz_target!(|input: &[u8]| exercise(input));

#[cfg(test)]
mod tests {
    use super::FUZZ_SECRET;
    use super::OUTPUT_BUDGETS;
    use super::VISIBLE_SENTINEL;
    use super::assert_secret_redacted;
    use super::assert_text_invariants;
    use super::encode_layers;
    use super::exercise;
    use super::generated_case;
    use super::log_safety;

    #[test]
    fn test_generated_cases_cover_all_syntax_and_entries() {
        let mut query_secret_positions = Vec::new();
        for case in 0..6 {
            for key_index in 0..3 {
                let generated = generated_case(case, key_index, 4, "a1b2");
                assert!(generated.input.contains(VISIBLE_SENTINEL) || case == 5);
                assert!(generated.contains_known_secret);
                match case {
                    0 => assert!(
                        generated
                            .input
                            .contains(["password", "pass%77ord", "%70assword"][key_index])
                    ),
                    1 => assert!(generated.input.contains(&format!("user:{FUZZ_SECRET}@"))),
                    2 => {
                        let query = generated.input.split_once('?').unwrap().1;
                        assert_eq!(query.matches("password=").count(), 2 + key_index % 3);
                        assert_eq!(query.matches('&').count(), 3 + key_index % 3);
                        query_secret_positions.push(
                            query
                                .split('&')
                                .position(|field| field.starts_with("password="))
                                .unwrap(),
                        );
                    }
                    3 => {
                        let inner = format!("https://inner.example/?password={FUZZ_SECRET}");
                        assert!(generated.input.contains(&encode_layers(&inner, 4)));
                    }
                    4 => assert!(generated.input.contains("password=https%3A%2F%2Finner.example")),
                    _ => {
                        assert!(generated.input.contains("password=%"));
                        assert!(generated.input.contains("%GG"));
                    }
                }
            }
        }
        query_secret_positions.sort_unstable();
        query_secret_positions.dedup();
        assert_eq!(query_secret_positions, [0, 1, 2]);
    }

    #[test]
    fn test_every_budget_and_nested_encoding_depth_runs_through_exercise() {
        for (budget_index, _) in OUTPUT_BUDGETS.iter().enumerate() {
            for depth in 1..=9 {
                for case in 0..6 {
                    let input = [case as u8, budget_index as u8, (depth - 1) as u8, 0xa5];
                    exercise(&input);
                }
            }
        }
    }

    #[test]
    fn test_empty_and_oversized_inputs_are_clamped() {
        exercise(&[]);
        exercise(&vec![b'x'; 4_096]);
        exercise(&vec![b'x'; 8_192]);
    }

    #[test]
    fn test_assertions_reject_oversized_unsafe_and_unredacted_text() {
        assert!(std::panic::catch_unwind(|| assert_text_invariants("12345", 4)).is_err());
        assert!(std::panic::catch_unwind(|| log_safety::assert_log_safe("line\nnext")).is_err());
        assert!(std::panic::catch_unwind(|| assert_secret_redacted(FUZZ_SECRET)).is_err());
    }
}
