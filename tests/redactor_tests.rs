// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for [`Redactor`](qubit_redact::Redactor).

use std::collections::BTreeMap;
use std::collections::HashMap;

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
/// Verifies repeated core-session fallbacks are charged and eventually become
/// empty rather than exceeding the cumulative output limit.
#[test]
fn test_redactor_session_fallbacks_respect_cumulative_output_limit() {
    let limit = InputOutputLimit::new(4, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the marker-sized operation limit should be valid");
    let policy = RedactionPolicy::builder()
        .ordinary_operation(limit)
        .build()
        .expect("the policy should build");
    let redactor = Redactor::new(policy);
    let session = RedactionSession::operation(redactor.policy());

    let rendered: Vec<_> = (0..5)
        .map(|_| {
            redactor
                .redact_at_with_session(
                    &session,
                    Sensitivity::Secret,
                    "raw-data",
                )
                .into_owned()
        })
        .collect();

    assert!(rendered.iter().any(String::is_empty));
    assert!(
        rendered.iter().map(String::len).sum::<usize>()
            <= limit.max_output_bytes()
    );
    assert_eq!(session.remaining_output_bytes(), 7);
}

/// Verifies the strict constructor masks fields that the standard policy leaves
/// unknown and visible.
#[test]
fn test_strict_redactor_masks_unknown_fields() {
    let standard = Redactor::default().redact_field("request_id", "raw");
    let strict = Redactor::strict().redact_field("request_id", "raw");

    assert!(!standard.is_masked());
    assert!(strict.is_masked());
    assert_eq!(strict.as_str(), "<redacted>");
}

/// Verifies an explicit sensitivity cannot be bypassed by a field allow rule.
#[test]
fn test_redact_at_ignores_field_allow_rules() {
    let policy = RedactionPolicy::builder()
        .allow_canonical_exact("password")
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy is valid");

    let redacted = Redactor::new(policy).redact_at(Sensitivity::Secret, "raw");

    assert_eq!(redacted.as_str(), "<redacted>");
}

/// Verifies that default field rules redact known secrets without changing the
/// source map.
#[test]
fn test_default_redactor_redacts_known_map_values() {
    let source = HashMap::from([
        ("username".to_string(), "alice".to_string()),
        ("password".to_string(), "secret".to_string()),
        ("OPENAI_API_KEY".to_string(), "sk-123".to_string()),
    ]);

    let redacted = Redactor::default().redact_map(&source);

    assert_eq!(redacted["username"], "alice");
    assert_eq!(redacted["password"], "<redacted>");
    assert_eq!(redacted["OPENAI_API_KEY"], "****");
    assert_eq!(source["password"], "secret");
}

/// Verifies that in-place map redaction supports ordered maps.
#[test]
fn test_redact_map_in_place_supports_btree_map() {
    let mut source = BTreeMap::from([
        ("password".to_string(), "secret".to_string()),
        ("username".to_string(), "alice".to_string()),
    ]);

    Redactor::default().redact_map_in_place(&mut source);

    assert_eq!(source["password"], "<redacted>");
    assert_eq!(source["username"], "alice");
}

/// Verifies copy redaction supports optional values without changing source.
#[test]
fn test_redact_map_copy_supports_optional_values() {
    let source = HashMap::from([
        ("label".to_owned(), Some("visible".to_owned())),
        ("password".to_owned(), Some("raw".to_owned())),
        ("secret".to_owned(), None),
    ]);

    let redacted = Redactor::default().redact_map(&source);

    assert_eq!(source["password"].as_deref(), Some("raw"));
    assert_eq!(redacted["label"].as_deref(), Some("visible"));
    assert_eq!(redacted["password"].as_deref(), Some("<redacted>"));
    assert_eq!(redacted["secret"], None);
}

/// Verifies that non-sensitive scalar values retain their input borrowing.
#[test]
fn test_redact_keeps_non_sensitive_value_borrowed() {
    let input = String::from("alice");
    let redacted = Redactor::default().redact_field("username", &input);

    assert!(std::ptr::eq(redacted.as_str(), input.as_str()));
}

/// Verifies session output accounting uses the escaped log length.
#[test]
fn test_redact_field_session_charges_escaped_bytes() {
    let limit = InputOutputLimit::new(64, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the diagnostic marker-sized limit should be valid");
    let policy = RedactionPolicy::builder()
        .ordinary_operation(limit)
        .build()
        .expect("the policy should build");
    let redactor = Redactor::new(policy);
    let session = RedactionSession::operation(redactor.policy());

    let result =
        redactor.redact_field_with_session(&session, "message", "a\n b");

    assert!(!result.is_masked());
    assert_eq!(
        session.remaining_output_bytes(),
        limit.max_output_bytes() - 5
    );
}
