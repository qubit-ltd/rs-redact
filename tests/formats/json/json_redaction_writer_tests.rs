// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! JSON parsing shapes and shared composer output allowances.

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

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
