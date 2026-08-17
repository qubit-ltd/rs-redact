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

use qubit_redact::FieldRedaction;
use qubit_redact::InputOutputLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// Verifies a mutable session uses the policy owned by its redactor.
#[test]
fn test_session_uses_redactor_policy_and_requires_mutable_access() {
    let redactor = Redactor::new(RedactionPolicy::strict());
    let mut session = redactor.session();
    let result = session.redact_field("message", "visible");
    assert!(matches!(result, FieldRedaction::Masked { .. }));
}

/// Verifies an output-closed session rejects work before charging more input.
#[test]
fn test_exhausted_session_does_not_charge_additional_input() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(1)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the marker-sized diagnostic limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let fallback = "<redacted>";
    let fallback_capacity = limit.max_output_bytes() / fallback.len();
    for _ in 0..fallback_capacity {
        assert_eq!(
            session
                .redact_at(Sensitivity::Secret, "first-too-large")
                .as_str(),
            fallback,
        );
    }
    let remaining = session.remaining_input_bytes();
    let second = session.redact_at(Sensitivity::Secret, "second");
    assert_eq!(second.as_str(), "");
    assert_eq!(session.remaining_input_bytes(), remaining);
}

/// Verifies repeated core-session fallbacks are charged and eventually become
/// empty rather than exceeding the cumulative output limit.
#[test]
fn test_redactor_session_fallbacks_respect_cumulative_output_limit() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(4)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the marker-sized operation limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let rendered: Vec<_> = (0..5)
        .map(|_| {
            session
                .redact_at(Sensitivity::Secret, "raw-data")
                .into_owned()
        })
        .collect();

    assert!(rendered.iter().any(String::is_empty));
    let rendered_bytes = rendered.iter().map(String::len).sum::<usize>();
    assert!(rendered_bytes <= limit.max_output_bytes());
    assert_eq!(session.remaining_output_bytes(), 0,);
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .legacy_fields()
            .allow_exact("password")
            .expect("the test builder input should be valid");
        builder
    })
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
    let limit = InputOutputLimit::builder()
        .max_input_bytes(64)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the diagnostic marker-sized limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
    })
    .build()
    .expect("the policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let result = session.redact_field("message", "a\n b");

    assert!(!result.is_masked());
    assert_eq!(
        session.remaining_output_bytes(),
        limit.max_output_bytes() - 5
    );
}

/// Verifies Unicode mask truncation closes a session even when the retained
/// prefix uses fewer bytes than the numeric byte ceiling.
#[test]
fn test_unicode_mask_truncation_closes_session() {
    let limit = InputOutputLimit::builder()
        .max_input_bytes(64)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the minimum output budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(limit);
        builder
            .legacy_fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed(&"你".repeat(20)))
            .expect("the Unicode replacement should be valid");
        builder
    })
    .build()
    .expect("the Unicode mask policy should build");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();

    let first = session.redact_at(Sensitivity::Secret, "secret");
    let input_after_first = session.remaining_input_bytes();
    let second = session.redact_at(Sensitivity::Secret, "another");

    assert_eq!(first.as_str(), "你".repeat(limit.max_output_bytes() / 3));
    assert_eq!(second.as_str(), "");
    assert_eq!(session.remaining_input_bytes(), input_after_first);
}
