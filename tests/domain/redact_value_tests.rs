// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for scalar redacted-value wrappers.

use std::borrow::Cow;

use qubit_redact::{
    MaskPolicy,
    MaskingPolicy,
    RedactValue,
    RedactedValue,
    Sensitivity,
};

/// Creates a masking policy whose secret mask contains a log control.
///
/// # Returns
///
/// A policy useful for verifying log escaping after masking.
fn create_control_masking_policy() -> MaskingPolicy {
    MaskingPolicy::default()
        .with_policy(Sensitivity::Secret, MaskPolicy::fixed("masked\nvalue"))
}

/// Verifies support for all borrowed and owned string forms.
#[test]
fn test_redact_value_supports_string_forms() {
    let masking = MaskingPolicy::default();
    let string = "raw-secret".to_owned();
    let slice: &str = &string;
    let reference = &slice;
    let borrowed: Cow<'_, str> = Cow::Borrowed(slice);
    let owned: Cow<'_, str> = Cow::Owned(string.clone());

    for value in [
        string.redact_value(Sensitivity::Secret, &masking),
        slice.redact_value(Sensitivity::Secret, &masking),
        reference.redact_value(Sensitivity::Secret, &masking),
        borrowed.redact_value(Sensitivity::Secret, &masking),
        owned.redact_value(Sensitivity::Secret, &masking),
    ] {
        assert_eq!(format!("{value:?}"), "\"<redacted>\"");
        assert_eq!(value.to_string(), "<redacted>");
    }
    assert_eq!(string, "raw-secret");
}

/// Verifies that option wrappers preserve `Some` and `None` shapes.
#[test]
fn test_redact_value_preserves_option_shape() {
    let masking = MaskingPolicy::default();
    let some = Some("raw-secret".to_owned());
    let borrowed = Some("raw-secret");
    let cow = Some(Cow::Borrowed("raw-secret"));
    let none: Option<String> = None;

    let redacted_some = some.redact_value(Sensitivity::Secret, &masking);
    let redacted_borrowed =
        borrowed.redact_value(Sensitivity::Secret, &masking);
    let redacted_cow = cow.redact_value(Sensitivity::Secret, &masking);
    let redacted_none = none.redact_value(Sensitivity::Secret, &masking);

    assert_eq!(format!("{redacted_some:?}"), "Some(\"<redacted>\")");
    assert_eq!(redacted_some.to_string(), "Some(<redacted>)");
    assert_eq!(format!("{redacted_borrowed:?}"), "Some(\"<redacted>\")");
    assert_eq!(format!("{redacted_cow:?}"), "Some(\"<redacted>\")");
    assert_eq!(format!("{redacted_none:?}"), "None");
    assert_eq!(redacted_none.to_string(), "None");
    assert!(matches!(redacted_some, RedactedValue::Some(_)));
    assert!(matches!(redacted_none, RedactedValue::None));
    assert_eq!(some.as_deref(), Some("raw-secret"));
}

/// Verifies that display escapes controls introduced by a configured mask.
#[test]
fn test_redacted_value_display_is_log_safe() {
    let masking = create_control_masking_policy();
    let value = "raw-secret".redact_value(Sensitivity::Secret, &masking);
    let optional =
        Some("raw-secret").redact_value(Sensitivity::Secret, &masking);

    assert_eq!(format!("{value:?}"), "\"masked\\nvalue\"");
    assert_eq!(value.to_string(), r"masked\nvalue");
    assert_eq!(optional.to_string(), r"Some(masked\nvalue)");
    assert!(!value.to_string().contains('\n'));
}

/// Verifies that masking empty borrowed text preserves its original borrow.
#[test]
fn test_redact_value_preserves_empty_borrow() {
    let input = String::new();
    let value =
        input.redact_value(Sensitivity::Secret, &MaskingPolicy::default());
    let RedactedValue::Text(text) = value else {
        panic!("plain text should retain the text variant");
    };

    assert!(std::ptr::eq(text.as_str(), input.as_str()));
}
