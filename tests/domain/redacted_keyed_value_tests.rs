// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedKeyedValue`](qubit_redact::domain::RedactedKeyedValue).

use std::fmt;

use qubit_redact::InputOutputLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::MaskingPolicy;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::domain::Redact;
#[cfg(feature = "serde")]
use qubit_redact::domain::RedactSerialize;
use qubit_redact::domain::RedactValue;
use qubit_redact::domain::RedactedKeyedResult;
use qubit_redact::domain::RedactedValue;
#[cfg(feature = "serde")]
use serde::Serializer;
#[cfg(feature = "serde")]
use serde_json::to_string;
/// Nested diagnostic value whose secret must be recursively redacted.
struct NestedValue {
    /// Secret nested value.
    secret: String,
    /// Visible descriptive text.
    label: String,
}

/// Verifies keyed-value display uses its policy output budget by default.
#[test]
fn test_redact_keyed_display_uses_policy_output_limit_by_default() {
    let budget =
        InputOutputLimit::new(1024, InputOutputLimit::MIN_OUTPUT_BYTES)
            .expect("the minimum diagnostic output limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the test policy should be valid");
    let redactor = Redactor::new(policy);
    let value = TextValue("visible diagnostic text".repeat(4));

    let output = redactor.redact_keyed("display_name", &value).to_string();

    assert!(output.len() <= budget.max_output_bytes());
    assert!(output.ends_with("<truncated>"));
}

/// Verifies keyed output is completed while the mutable session is available.
#[test]
fn test_redacted_keyed_result_is_settled_at_creation() {
    let redactor = Redactor::default();
    let value = TextValue("visible".to_owned());
    let mut session = redactor.session();
    let result = RedactedKeyedResult::new("display_name", &value, &mut session);

    assert_eq!(format!("{:?}", result), "\"visible\"");
}

/// Textual value that supports both keyed masking and recursive formatting.
struct TextValue(String);

/// Value used to verify formatter flags and formatter failures.
struct FormatterBehavior {
    fail: bool,
}

impl Redact for FormatterBehavior {
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        if self.fail {
            return Err(fmt::Error);
        }
        formatter.write_str(if formatter.alternate() {
            "alternate"
        } else {
            "compact"
        })
    }
}

impl RedactValue for FormatterBehavior {
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        RedactedValue::opaque(level, masking)
    }
}

impl Redact for TextValue {
    /// Formats the visible text without adding nested redaction rules.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
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
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        self.0.redact_value(level, masking)
    }
}

impl Redact for NestedValue {
    /// Formats the nested value without exposing its secret.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter
            .debug_struct("NestedValue")
            .field(
                "secret",
                &self.secret.redact_value(
                    Sensitivity::Secret,
                    _session.policy().masking(),
                ),
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
        masking: &MaskingPolicy,
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
        S: Serializer,
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("tenant_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("tenant_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
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

/// Verifies eager keyed completion forwards alternate debug.
#[test]
fn test_redact_keyed_preserves_alternate_debug() {
    let value = FormatterBehavior { fail: false };
    let redactor = Redactor::default();

    assert_eq!(
        format!("{:?}", redactor.redact_keyed("label", &value)),
        "compact"
    );
    assert_eq!(
        format!("{:#?}", redactor.redact_keyed("label", &value)),
        "alternate"
    );
}

/// Verifies an inner formatter error is returned rather than hidden by eager
/// completion.
#[test]
fn test_redact_keyed_preserves_formatter_error() {
    let value = FormatterBehavior { fail: true };
    let redactor = Redactor::default();
    let mut output = String::new();

    let result = fmt::write(
        &mut output,
        format_args!("{:?}", redactor.redact_keyed("label", &value)),
    );

    assert_eq!(result, Err(fmt::Error));
}

/// Value that verifies opaque masks are bounded before allocation completes.
struct OpaqueMaskObserver;

impl Redact for OpaqueMaskObserver {
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str("visible")
    }
}

impl RedactValue for OpaqueMaskObserver {
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        let redacted = RedactedValue::opaque(level, masking);
        let RedactedValue::Text(text) = &redacted else {
            panic!("opaque masking must retain plain text shape");
        };
        assert!(text.as_str().len() <= InputOutputLimit::MIN_OUTPUT_BYTES);
        redacted
    }
}

/// Verifies eager completion installs its admitted mask ceiling before an
/// opaque replacement is materialized.
#[test]
fn test_redact_keyed_bounds_opaque_mask_before_materialization() {
    let budget =
        InputOutputLimit::new(1024, InputOutputLimit::MIN_OUTPUT_BYTES)
            .expect("the minimum output budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
            .fields()
            .raise("tenant_secret", Sensitivity::Secret)
            .expect("the test field should be valid");
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed(&"x".repeat(1_000)))
            .expect("the replacement should be valid");
        builder
    })
    .build()
    .expect("the test policy should build");
    let redactor = Redactor::new(policy);

    let output = format!(
        "{:?}",
        redactor.redact_keyed("tenant_secret", &OpaqueMaskObserver)
    );

    assert!(output.len() <= budget.max_output_bytes());
}

/// Keyed value that records whether domain rendering reaches its formatter.
struct ObservedKeyedValue<'a>(&'a std::sync::atomic::AtomicUsize);

impl Redact for ObservedKeyedValue<'_> {
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        formatter.write_str("must-not-render")
    }
}

impl RedactValue for ObservedKeyedValue<'_> {
    fn redact_value<'a>(
        &'a self,
        level: Sensitivity,
        masking: &MaskingPolicy,
    ) -> RedactedValue<'a> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        RedactedValue::opaque(level, masking)
    }
}

/// Verifies keyed domain rendering does not charge diagnostic input for values.
#[test]
fn test_redact_keyed_does_not_charge_value_input() {
    let visits = std::sync::atomic::AtomicUsize::new(0);
    let budget = InputOutputLimit::new(1, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the minimum diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the policy should build");
    let redactor = Redactor::new(policy);

    let output = format!(
        "{:?}",
        redactor.redact_keyed("label", &ObservedKeyedValue(&visits))
    );

    assert_eq!(output, "must-not-render");
    assert_eq!(visits.load(std::sync::atomic::Ordering::Relaxed), 1);
}

/// Verifies keyed values serialize their selected redacted representation.
#[cfg(feature = "serde")]
#[test]
fn test_redact_keyed_serializes_sensitive_and_recursive_values() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("tenant_secret", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the test policy should be valid");
    let value = nested_value();
    let redactor = Redactor::new(policy);
    let sensitive = redactor.redact_keyed("tenant_secret", &value);
    let visible = redactor.redact_keyed("display_name", &value);
    let sensitive_json =
        to_string(&sensitive).expect("the redacted value should serialize");
    let visible_json =
        to_string(&visible).expect("the recursive value should serialize");

    assert_eq!(sensitive_json, "\"<redacted>\"");
    assert!(visible_json.contains("visible-label"));
    assert!(!visible_json.contains("nested-secret"));
}
