// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for typed scalar field-redaction results.

use qubit_redact::{
    FieldRedaction,
    PassThroughReason,
    RedactionPolicy,
    Redactor,
    Sensitivity,
};

/// Verifies masked fields expose a typed masked result.
#[test]
fn test_redact_field_reports_masked_result() {
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should be valid");

    let result = Redactor::new(policy).redact_field("tenant_secret", "raw");

    assert!(matches!(
        &result,
        FieldRedaction::Masked {
            sensitivity: Sensitivity::Secret,
            ..
        }
    ));
    assert!(result.is_masked());
    assert_eq!(result.as_str(), "<redacted>");
    assert_eq!(result.sensitivity(), Some(Sensitivity::Secret));
    assert_eq!(result.pass_through_reason(), None);
    assert_eq!(result.clone().escape_for_log().as_str(), "<redacted>");
    assert_eq!(result.into_owned(), "<redacted>");
}

/// Verifies allowed and unknown fields expose why their values were retained.
#[test]
fn test_redact_field_reports_pass_through_reason() {
    let policy = RedactionPolicy::builder()
        .disable_floor()
        .allow_canonical_exact("display_name")
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should be valid");
    let redactor = Redactor::new(policy);

    let allowed = redactor.redact_field("display_name", "Alice");
    let unknown = redactor.redact_field("other", "visible");

    assert_eq!(
        allowed.pass_through_reason(),
        Some(PassThroughReason::Allowed)
    );
    assert_eq!(
        unknown.pass_through_reason(),
        Some(PassThroughReason::Unknown)
    );
    assert!(!allowed.is_masked());
    assert!(!unknown.is_masked());
    assert_eq!(allowed.as_str(), "Alice");
    assert_eq!(allowed.sensitivity(), None);
    assert_eq!(allowed.into_owned(), "Alice");
    assert_eq!(unknown.escape_for_log().as_str(), "visible");
}

/// Verifies Debug remains available for inspecting processed field results.
#[test]
fn test_redact_field_debug_is_available() {
    let result = Redactor::default().redact_field("password", "raw");
    let debug = format!("{result:?}");

    assert!(debug.contains("Masked"));
    assert!(debug.contains("<redacted>"));
}
