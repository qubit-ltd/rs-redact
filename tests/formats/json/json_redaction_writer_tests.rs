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
    assert_eq!(output.summary().completion(), expected_completion);
    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert_eq!(
        output.summary().reasons().contains(RedactionReason::OutputLimitReached),
        rejected
    );
}
