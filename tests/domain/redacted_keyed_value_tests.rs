// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedKeyedValue`](qubit_redact::RedactedKeyedValue).

use std::fmt;

use qubit_redact::{
    Redact,
    RedactValue,
    RedactedValue,
    RedactionPolicy,
    Redactor,
    Sensitivity,
};

#[cfg(feature = "serde")]
use qubit_redact::domain::RedactSerialize;

/// Nested diagnostic value whose secret must be recursively redacted.
struct NestedValue {
    /// Secret nested value.
    secret: String,
    /// Visible descriptive text.
    label: String,
}

/// Textual value that supports both keyed masking and recursive formatting.
struct TextValue(String);

impl Redact for TextValue {
    /// Formats the visible text without adding nested redaction rules.
    fn fmt_redacted(
        &self,
        _policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        fmt::Debug::fmt(&self.0, formatter)
    }
}

impl RedactValue for TextValue {
    /// Redacts the complete textual value at the selected sensitivity.
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &'a qubit_redact::MaskingPolicy,
    ) -> RedactedValue<'a> {
        self.0.redact_value(level, masking)
    }
}

impl Redact for NestedValue {
    /// Formats the nested value without exposing its secret.
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter
            .debug_struct("NestedValue")
            .field(
                "secret",
                &self
                    .secret
                    .redact_value(Sensitivity::Secret, policy.masking()),
            )
            .field("label", &self.label)
            .finish()
    }
}

impl RedactValue for NestedValue {
    /// Replaces the complete nested value when its outer key is sensitive.
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &'a qubit_redact::MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

#[cfg(feature = "serde")]
impl RedactSerialize for NestedValue {
    /// Serializes the nested value without exposing its secret.
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("NestedValue", 2)?;
        state.serialize_field(
            "secret",
            &self
                .secret
                .redact_value(Sensitivity::Secret, policy.masking()),
        )?;
        state.serialize_field("label", &self.label)?;
        state.end()
    }
}

/// Creates a value containing both a nested secret and a visible field.
///
/// # Returns
///
/// A stable test value for keyed redaction behavior.
fn nested_value() -> NestedValue {
    NestedValue {
        secret: "nested-secret".to_owned(),
        label: "visible-label".to_owned(),
    }
}

/// Verifies a sensitive keyed text view masks Debug and log-safe Display.
#[test]
fn test_redact_keyed_masks_sensitive_text_for_debug_and_display() {
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the test policy should be valid");
    let redactor = Redactor::new(policy);
    let value = TextValue("raw\nsecret".to_owned());
    let view = redactor.redact_keyed("tenant_secret", &value);

    assert_eq!(format!("{view:?}"), "\"<redacted>\"");
    assert_eq!(view.to_string(), "\"<redacted>\"");
    assert!(!format!("{view:?}").contains("raw"));
    assert!(!view.to_string().contains('\n'));
}

/// Verifies a sensitive keyed non-text value uses an opaque replacement.
#[test]
fn test_redact_keyed_masks_sensitive_non_text_value() {
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the test policy should be valid");
    let value = nested_value();
    let redactor = Redactor::new(policy);
    let view = redactor.redact_keyed("tenant_secret", &value);

    assert_eq!(format!("{view:?}"), "\"<redacted>\"");
    assert!(!format!("{view:?}").contains("nested-secret"));
}

/// Verifies an unclassified outer key recursively redacts nested content.
#[test]
fn test_redact_keyed_recursively_redacts_unclassified_value() {
    let value = nested_value();
    let redactor = Redactor::default();
    let view = redactor.redact_keyed("display_name", &value);
    let debug = format!("{view:?}");
    let display = view.to_string();

    assert!(debug.contains("visible-label"));
    assert!(!debug.contains("nested-secret"));
    assert!(!display.contains("nested-secret"));
    assert!(!display.contains('\n'));
}

/// Verifies a keyed redacted view retains its original field name.
#[test]
fn test_redact_keyed_preserves_key() {
    let value = TextValue("visible".to_owned());
    let redactor = Redactor::default();
    let view = redactor.redact_keyed("display_name", &value);

    assert_eq!(view.key(), "display_name");
}

/// Verifies keyed values serialize their selected redacted representation.
#[cfg(feature = "serde")]
#[test]
fn test_redact_keyed_serializes_sensitive_and_recursive_values() {
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the test policy should be valid");
    let value = nested_value();
    let redactor = Redactor::new(policy);
    let sensitive = redactor.redact_keyed("tenant_secret", &value);
    let visible = redactor.redact_keyed("display_name", &value);
    let sensitive_json = serde_json::to_string(&sensitive)
        .expect("the redacted value should serialize");
    let visible_json = serde_json::to_string(&visible)
        .expect("the recursive value should serialize");

    assert_eq!(sensitive_json, "\"<redacted>\"");
    assert!(visible_json.contains("visible-label"));
    assert!(!visible_json.contains("nested-secret"));
}
