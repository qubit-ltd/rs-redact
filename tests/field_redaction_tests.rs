// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for final scalar field-redaction output.

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// Verifies a sensitive field produces final masked text and completion data.
#[test]
fn test_redact_field_returns_final_masked_output() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise("tenant_secret", Sensitivity::Secret);
        })
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should be valid");

    let result = Redactor::new(policy).redact_field("tenant_secret", "raw");

    assert_eq!(result.text().as_str(), "<redacted>");
    assert_eq!(result.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(result.summary().usage().output_bytes(), "<redacted>".len());
}

/// Verifies explicit allows and unknown fields are retained in final output.
#[test]
fn test_redact_field_preserves_explicitly_allowed_and_unknown_values() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor().allow_exact("display_name");
        })
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should be valid");
    let redactor = Redactor::new(policy);

    let allowed = redactor.redact_field("display_name", "Alice");
    let unknown = redactor.redact_field("other", "visible");

    assert_eq!(allowed.text().as_str(), "Alice");
    assert_eq!(unknown.text().as_str(), "visible");
    assert_eq!(allowed.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(unknown.summary().completion(), RedactionCompletion::Complete);
}

/// Verifies the public result is the final output model, rather than a typed
/// intermediate scalar-result enum.
#[test]
fn test_redact_field_debug_describes_final_output() {
    let result = Redactor::default().redact_field("password", "raw");
    let debug = format!("{result:?}");

    assert!(debug.contains("RedactionTextOutput"));
    assert!(debug.contains("<redacted>"));
}

/// Exercises display-field masking, disabled pass-through, and bounded raw
/// formatting through the public scalar API.
#[test]
fn test_redact_display_field_covers_masking_and_output_boundaries() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise("partial", Sensitivity::Low);
        })
        .expect("the test field rule should be valid")
        .build()
        .expect("the policy should be valid");
    let masked = Redactor::new(policy).redact_field("partial", &format_args!("account-42"));
    assert!(!masked.text().as_str().contains("account-42"));
    assert_eq!(masked.summary().completion(), RedactionCompletion::Complete);

    let visible = Redactor::new(RedactionPolicy::disabled()).redact_field("password", &format_args!("visible"));
    assert_eq!(visible.text().as_str(), "visible");

    let limited = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor();
        })
        .expect("the test field policy should be valid")
        .limits(|limits| {
            limits.max_output_bytes(2);
        })
        .expect("the test limits should be valid")
        .build()
        .expect("the policy should be valid");
    let exhausted = Redactor::new(limited).redact_field("visible", &format_args!("long-value"));
    assert!(exhausted.text().as_str().is_empty());
    assert_eq!(exhausted.summary().completion(), RedactionCompletion::Exhausted);
}
