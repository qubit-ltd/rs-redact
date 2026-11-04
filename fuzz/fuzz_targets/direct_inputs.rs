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
use qubit_redact::RedactionInspection;
use qubit_redact::RedactionInspectionError;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionTextOutput;
use qubit_redact::Redactor;
use qubit_redact::formats::uri::UriRedactionBoundary;

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
    expectation: InspectionExpectation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InspectionExpectation {
    Sensitive,
    Ordinary,
    Malformed,
}

#[derive(Clone, Copy, Debug)]
enum InspectionBudget {
    Input(usize),
    Nodes(usize),
    Depth(usize),
    Collection(usize),
    Key(usize),
}

fn selected_inspection_budget(index: usize, input_len: usize) -> InspectionBudget {
    let policy = RedactionPolicy::standard();
    let limits = policy.limits();
    match index % 20 {
        0 => InspectionBudget::Input(0),
        1 => InspectionBudget::Input(input_len.saturating_sub(1)),
        2 => InspectionBudget::Input(input_len),
        3 => InspectionBudget::Input(input_len.saturating_add(1)),
        4 => InspectionBudget::Nodes(0),
        5 => InspectionBudget::Nodes(1),
        6 => InspectionBudget::Nodes(2),
        7 => InspectionBudget::Nodes(limits.max_nodes().unwrap_or(usize::MAX)),
        8 => InspectionBudget::Depth(0),
        9 => InspectionBudget::Depth(1),
        10 => InspectionBudget::Depth(2),
        11 => InspectionBudget::Depth(limits.max_depth().unwrap_or(usize::MAX)),
        12 => InspectionBudget::Collection(0),
        13 => InspectionBudget::Collection(1),
        14 => InspectionBudget::Collection(2),
        15 => InspectionBudget::Collection(limits.max_collection_items().unwrap_or(usize::MAX)),
        16 => InspectionBudget::Key(0),
        17 => InspectionBudget::Key(7),
        18 => InspectionBudget::Key(8),
        _ => InspectionBudget::Key(limits.max_key_bytes().unwrap_or(usize::MAX)),
    }
}

fn inspection_limited_redactor(budget: InspectionBudget, input_len: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            match budget {
                InspectionBudget::Input(value) => limits.max_input_bytes(if value == usize::MAX {
                    input_len.saturating_add(1)
                } else {
                    value
                }),
                InspectionBudget::Nodes(value) => limits.max_nodes(value),
                InspectionBudget::Depth(value) => limits.max_depth(value),
                InspectionBudget::Collection(value) => limits.max_collection_items(value),
                InspectionBudget::Key(value) => limits.max_key_bytes(value),
            };
        })
        .expect("inspection limits valid")
        .build()
        .expect("inspection policy valid");
    Redactor::new(policy)
}

fn assert_usage(result: &Result<RedactionInspection, RedactionInspectionError>, max_input: usize) {
    let usage = match result {
        Ok(value) => value.usage(),
        Err(error) => error.usage(),
    };
    assert!(usage.inspected_input_bytes() <= max_input);
    assert_eq!(usage.output_bytes(), 0);
}

fn assert_sensitive_or_error(result: Result<RedactionInspection, RedactionInspectionError>) {
    if let Ok(inspection) = result {
        assert!(inspection.contains_sensitive(), "known secret classified as public");
    }
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
    let (input, entry, preserves_visible_sentinel) = match case % 7 {
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
        5 => (
            format!("https://fuzz.example/?password=%{FUZZ_SECRET}%GG&visible={visible}%FF&ordinary=%GG"),
            Entry::Both,
            false,
        ),
        _ => ("https://fuzz.example/?name=ada".to_owned(), Entry::Both, false),
    };
    GeneratedCase {
        input,
        entry,
        contains_known_secret: case % 7 != 6,
        preserves_visible_sentinel,
        expectation: match case % 7 {
            5 => InspectionExpectation::Malformed,
            6 => InspectionExpectation::Ordinary,
            _ => InspectionExpectation::Sensitive,
        },
    }
}

#[cfg(test)]
fn ordinary_case() -> GeneratedCase {
    generated_case(6, 0, 1, "")
}

fn inspect_case(redactor: &Redactor, boundary: &UriRedactionBoundary, generated: &GeneratedCase) {
    let standard_boundary = UriRedactionBoundary::new(&RedactionPolicy::standard());
    for entry in match generated.entry {
        Entry::Http => [Some(Entry::Http), None],
        Entry::Uri => [Some(Entry::Uri), None],
        Entry::Both => [Some(Entry::Http), Some(Entry::Uri)],
    }
    .into_iter()
    .flatten()
    {
        let check = |r: &Redactor| match entry {
            Entry::Http => r.inspect_http_url(&generated.input),
            Entry::Uri => r.inspect_uri(&generated.input),
            _ => unreachable!(),
        };
        let first = check(redactor);
        let second = check(redactor);
        assert_eq!(first, second, "inspection must be deterministic");
        assert_usage(&first, redactor.policy().limits().max_input_bytes());
        if generated.expectation == InspectionExpectation::Sensitive {
            assert_sensitive_or_error(first);
            let successful = check(&Redactor::standard()).expect("sufficient standard budget");
            assert!(successful.contains_sensitive());
            assert!(successful.usage().inspected_input_bytes() <= generated.input.len());
            assert_eq!(successful.usage().output_bytes(), 0);
        } else if generated.expectation == InspectionExpectation::Ordinary {
            assert!(first.as_ref().expect("ordinary URL succeeds").contains_sensitive() == false);
        } else if entry == Entry::Uri {
            assert!(first.is_err(), "malformed generic URI must be rejected");
        } else {
            assert_sensitive_or_error(first);
        }
        if entry == Entry::Uri {
            let boundary_result = boundary.inspect_uri(&generated.input);
            match generated.expectation {
                InspectionExpectation::Sensitive => assert_sensitive_or_error(boundary_result),
                InspectionExpectation::Ordinary => assert!(
                    !boundary_result
                        .expect("ordinary boundary URL succeeds")
                        .contains_sensitive()
                ),
                InspectionExpectation::Malformed => {}
            }
            let standard_result = standard_boundary.inspect_uri(&generated.input);
            match generated.expectation {
                InspectionExpectation::Sensitive => assert_sensitive_or_error(standard_result),
                InspectionExpectation::Ordinary => assert!(
                    !standard_result
                        .expect("ordinary standard boundary succeeds")
                        .contains_sensitive()
                ),
                InspectionExpectation::Malformed => {}
            }
        }
    }
}

fn inspect_with_budget(generated: &GeneratedCase, budget: InspectionBudget) {
    let limited = inspection_limited_redactor(budget, generated.input.len());
    let boundary = UriRedactionBoundary::new(limited.policy());
    for entry in match generated.entry {
        Entry::Http => [Some(Entry::Http), None],
        Entry::Uri => [Some(Entry::Uri), None],
        Entry::Both => [Some(Entry::Http), Some(Entry::Uri)],
    }
    .into_iter()
    .flatten()
    {
        let result = match entry {
            Entry::Http => limited.inspect_http_url(&generated.input),
            Entry::Uri => limited.inspect_uri(&generated.input),
            _ => unreachable!(),
        };
        assert_usage(&result, limited.policy().limits().max_input_bytes());
        match generated.expectation {
            InspectionExpectation::Sensitive => assert_sensitive_or_error(result),
            InspectionExpectation::Ordinary => {
                if let Ok(inspection) = result {
                    assert!(!inspection.contains_sensitive(), "ordinary URL classified sensitive");
                }
            }
            InspectionExpectation::Malformed if entry == Entry::Uri => assert!(result.is_err()),
            InspectionExpectation::Malformed => assert_sensitive_or_error(result),
        }
        if entry == Entry::Uri && generated.expectation == InspectionExpectation::Sensitive {
            assert_sensitive_or_error(boundary.inspect_uri(&generated.input));
        }
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

    let case_index = usize::from(input.first().copied().unwrap_or_default()) % 7;
    let budget_index = usize::from(input.get(1).copied().unwrap_or_default()) % OUTPUT_BUDGETS.len();
    let depth = usize::from(input.get(2).copied().unwrap_or_default()) % 9 + 1;
    let noise = bounded_noise(input.get(3..).unwrap_or_default());
    let generated = generated_case(case_index, budget_index, depth, &noise);
    let redactor = output_limited_redactor(OUTPUT_BUDGETS[budget_index]);
    let inspection_redactor = Redactor::standard();
    let boundary = UriRedactionBoundary::new(&RedactionPolicy::disabled());
    inspect_case(&inspection_redactor, &boundary, &generated);
    let selected = usize::from(input.get(3).copied().unwrap_or_default());
    inspect_with_budget(&generated, selected_inspection_budget(selected, generated.input.len()));

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
    use qubit_redact::RedactionPolicy;
    use qubit_redact::Redactor;
    use qubit_redact::formats::uri::UriRedactionBoundary;

    use super::FUZZ_SECRET;
    use super::InspectionBudget;
    use super::InspectionExpectation;
    use super::OUTPUT_BUDGETS;
    use super::VISIBLE_SENTINEL;
    use super::assert_secret_redacted;
    use super::assert_sensitive_or_error;
    use super::assert_text_invariants;
    use super::encode_layers;
    use super::exercise;
    use super::generated_case;
    use super::inspect_with_budget;
    use super::log_safety;

    #[test]
    fn test_generated_cases_cover_all_syntax_and_entries() {
        let mut query_secret_positions = Vec::new();
        for case in 0..7 {
            for key_index in 0..3 {
                let generated = generated_case(case, key_index, 4, "a1b2");
                assert!(generated.input.contains(VISIBLE_SENTINEL) || case >= 5);
                assert_eq!(generated.contains_known_secret, case != 6);
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
                    5 => {
                        assert!(generated.input.contains("password=%"));
                        assert!(generated.input.contains("%GG"));
                    }
                    _ => assert_eq!(generated.input, "https://fuzz.example/?name=ada"),
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
                for case in 0..7 {
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

    #[test]
    fn test_inspection_admission_properties_and_oracle() {
        let redactor = Redactor::standard();
        let uri = "https://fuzz.example/?password=raw-secret";
        assert!(redactor.inspect_uri(uri).unwrap().contains_sensitive());
        assert!(redactor.inspect_http_url(uri).unwrap().contains_sensitive());
        assert!(
            !redactor
                .inspect_uri("https://fuzz.example/?name=ada")
                .unwrap()
                .contains_sensitive()
        );
        let boundary = UriRedactionBoundary::new(&RedactionPolicy::disabled());
        assert!(boundary.inspect_uri(uri).unwrap().contains_sensitive());
        assert!(redactor.inspect_uri("https://fuzz.example/?password=%GG").is_err());
        assert!(redactor.inspect_uri("https://fuzz.example/?password=%FF").is_err());

        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_output_bytes(0);
            })
            .unwrap()
            .build()
            .unwrap();
        let zero_output = Redactor::new(policy).inspect_uri(uri).unwrap();
        assert!(zero_output.contains_sensitive());
        assert_eq!(zero_output.usage().output_bytes(), 0);

        let zero_input = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_input_bytes(0);
            })
            .unwrap()
            .build()
            .unwrap();
        assert!(Redactor::new(zero_input).inspect_uri(uri).is_err());
        let zero_nodes = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(0);
            })
            .unwrap()
            .build()
            .unwrap();
        assert!(Redactor::new(zero_nodes).inspect_uri(uri).is_err());

        let ordinary = redactor.inspect_uri("https://fuzz.example/?name=ada").unwrap();
        assert!(std::panic::catch_unwind(|| assert_sensitive_or_error(Ok(ordinary))).is_err());
        assert!(
            redactor.inspect_uri(uri).unwrap().contains_sensitive(),
            "strong success control"
        );

        let mut counts = [0usize; 3];
        for case in 0..7 {
            let generated = super::generated_case(case, 1, 4, "");
            let index = match generated.expectation {
                InspectionExpectation::Sensitive => 0,
                InspectionExpectation::Ordinary => 1,
                InspectionExpectation::Malformed => 2,
            };
            counts[index] += 1;
            super::inspect_case(&redactor, &boundary, &generated);
        }
        let ordinary_case = super::ordinary_case();
        counts[1] += 1;
        super::inspect_case(&redactor, &boundary, &ordinary_case);
        assert!(counts.iter().all(|count| *count > 0));
    }

    #[test]
    fn test_independent_inspection_budget_boundaries() {
        let mut category_counts = [0usize; 7];
        let standard_policy = RedactionPolicy::standard();
        let limits = standard_policy.limits();
        let standard_nodes = limits.max_nodes().unwrap_or(usize::MAX);
        let standard_depth = limits.max_depth().unwrap_or(usize::MAX);
        let standard_collection = limits.max_collection_items().unwrap_or(usize::MAX);
        let standard_key = limits.max_key_bytes().unwrap_or(usize::MAX);
        for case in 0..7 {
            let generated = super::generated_case(case, 1, 4, "");
            category_counts[case] += 1;
            let len = generated.input.len();
            let budgets = [
                InspectionBudget::Input(0),
                InspectionBudget::Input(len.saturating_sub(1)),
                InspectionBudget::Input(len),
                InspectionBudget::Input(len.saturating_add(1)),
                InspectionBudget::Nodes(0),
                InspectionBudget::Nodes(1),
                InspectionBudget::Nodes(2),
                InspectionBudget::Nodes(standard_nodes),
                InspectionBudget::Depth(0),
                InspectionBudget::Depth(1),
                InspectionBudget::Depth(2),
                InspectionBudget::Depth(standard_depth),
                InspectionBudget::Collection(0),
                InspectionBudget::Collection(1),
                InspectionBudget::Collection(2),
                InspectionBudget::Collection(standard_collection),
                InspectionBudget::Key(0),
                InspectionBudget::Key(7),
                InspectionBudget::Key(8),
                InspectionBudget::Key(standard_key),
            ];
            for budget in budgets {
                inspect_with_budget(&generated, budget);
            }
        }
        assert!(category_counts.iter().all(|count| *count > 0));
        let ordinary_case = super::ordinary_case();
        for budget in [
            InspectionBudget::Input(ordinary_case.input.len()),
            InspectionBudget::Nodes(standard_nodes),
            InspectionBudget::Depth(standard_depth),
            InspectionBudget::Collection(standard_collection),
            InspectionBudget::Key(standard_key),
        ] {
            inspect_with_budget(&ordinary_case, budget);
        }
        let sensitive = super::generated_case(0, 0, 1, "");
        let zero_input = super::inspection_limited_redactor(InspectionBudget::Input(0), sensitive.input.len());
        assert!(zero_input.inspect_uri(&sensitive.input).is_err());
        let zero_nodes = super::inspection_limited_redactor(InspectionBudget::Nodes(0), sensitive.input.len());
        assert!(zero_nodes.inspect_uri(&sensitive.input).is_err());
        let ordinary = "https://fuzz.example/?name=ada";
        assert!(
            !Redactor::standard()
                .inspect_uri(ordinary)
                .expect("ordinary URI succeeds")
                .contains_sensitive()
        );
        assert!(
            super::inspection_limited_redactor(InspectionBudget::Input(0), ordinary.len())
                .inspect_uri(ordinary)
                .is_err()
        );
        assert!(
            super::inspection_limited_redactor(InspectionBudget::Nodes(0), ordinary.len())
                .inspect_uri(ordinary)
                .is_err()
        );
    }
}
