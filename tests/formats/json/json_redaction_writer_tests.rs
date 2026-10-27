// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! JSON parsing shapes and shared composer output allowances.

use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

#[test]
fn test_json_text_preserves_native_numbers_with_unified_serde_json_features() {
    for (text, expected_text) in [
        ("1.5", "1.5"),
        ("1e2", "100.0"),
        ("-0.0", "-0.0"),
        ("-9223372036854775808", "-9223372036854775808"),
        ("18446744073709551615", "18446744073709551615"),
        (
            r#"{"amount":1.5,"values":[-0.0,1e2,-9223372036854775808]}"#,
            r#"{"amount":1.5,"values":[-0.0,100.0,-9223372036854775808]}"#,
        ),
    ] {
        let output = Redactor::standard().redact_json(text);
        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
        assert_eq!(output.text().as_str(), expected_text, "input: {text}");
        Redactor::standard()
            .inspect_json(text)
            .expect("the same JSON numbers should be inspectable");
    }
}

#[test]
fn test_json_number_consumes_one_structural_node() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1);
        })
        .expect("the test limit draft should build")
        .build()
        .expect("the test policy should build");
    let output = Redactor::new(policy).redact_json("1.5");

    assert_eq!(output.text().as_str(), "1.5");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.summary().usage().visited_nodes(), 1);
    assert_eq!(output.summary().usage().visited_collection_items(), 0);
}

#[test]
fn test_json_text_preserves_literal_private_protocol_keys() {
    for text in [
        r#"{"$serde_json::private::Number":"1.5"}"#,
        r#"{"$serde_json::private::RawValue":"1.5"}"#,
    ] {
        let output = Redactor::standard().redact_json(text);

        assert_eq!(output.text().as_str(), text);
        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    }
}

#[test]
fn test_json_text_rejects_decoded_duplicate_keys_without_exposing_values() {
    let source = r#"{"password":"first-secret","pass\u0077ord":"second-secret"}"#;
    let redactor = Redactor::standard();
    let output = redactor.redact_json(source);

    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert!(!output.text().as_str().contains("first-secret"));
    assert!(!output.text().as_str().contains("second-secret"));
    assert!(redactor.inspect_json(source).is_err());
}

#[test]
fn test_admitted_json_tree_covers_every_scalar_parser_representation() {
    for text in [
        "null",
        "true",
        "-1",
        "1",
        "1.5",
        r#""visible""#,
        r#"[null,true,-1,1,1.5,"visible"]"#,
    ] {
        let output = Redactor::standard().redact_json(text);

        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    }
}

/// Verifies a JSON adapter sees bytes already committed by the enclosing
/// transaction when choosing its rendering limit.
#[test]
fn test_json_session_uses_the_transaction_remaining_output_allowance() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(20);
        })
        .expect("the test limit draft should build")
        .build()
        .expect("the test policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .literal("prefix")
        .json(|json| {
            json.text(r#"{"description":"this value is deliberately longer than the allowance"}"#);
        })
        .finish();

    assert_eq!(output.text().as_str(), "prefix<truncated>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(output.summary().usage().output_bytes(), 17);
}

#[test]
fn test_invalid_json_masking_respects_escaped_output_allowances() {
    let cases = [
        ("ok", 2, "ok", RedactionCompletion::Complete, false),
        ("ok", 1, "", RedactionCompletion::Exhausted, true),
        ("\n", 2, "\\n", RedactionCompletion::Complete, false),
        ("\n", 1, "", RedactionCompletion::Exhausted, true),
        ("账户", 6, "账户", RedactionCompletion::Complete, false),
        ("账户", 5, "", RedactionCompletion::Exhausted, true),
        ("\u{202e}", 8, "\\u{202e}", RedactionCompletion::Complete, false),
        ("\u{202e}", 7, "", RedactionCompletion::Exhausted, true),
    ];

    for (mask, allowance, expected_text, expected_completion, rejected) in cases {
        assert_invalid_json_case(mask, allowance, expected_text, expected_completion, rejected);
    }

    let large_mask = "x".repeat(128 * 1024);
    assert_invalid_json_case(&large_mask, 10, "", RedactionCompletion::Exhausted, true);
    assert_invalid_json_case(&large_mask, 11, "<truncated>", RedactionCompletion::Truncated, true);
}

fn assert_invalid_json_case(
    mask: &str,
    allowance: usize,
    expected_text: &str,
    expected_completion: RedactionCompletion,
    rejected: bool,
) {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .sensitive(Sensitivity::Secret, "password")
                .mask(Sensitivity::Secret, MaskPolicy::fixed(mask));
        })
        .expect("field policy should build")
        .limits(|limits| {
            let _ = limits.max_output_bytes(allowance);
        })
        .expect("limits should be accepted")
        .build()
        .expect("policy should build");
    let output = Redactor::new(policy).redact_json("{");

    assert_eq!(output.text().as_str(), expected_text);
    assert_eq!(
        output.summary().completion(),
        expected_completion,
        "mask length {}, allowance {allowance}",
        mask.len()
    );
    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert_eq!(
        output.summary().reasons().contains(RedactionReason::OutputLimitReached),
        rejected
    );
}
