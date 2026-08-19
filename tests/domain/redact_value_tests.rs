// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Tests for scalar redacted value representations.

use std::borrow::Cow;

use qubit_redact::MaskingPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::domain::RedactValue;

/// Every supported scalar input shape retains its intended visible container
/// shape after masking.  Debug is deliberately used here because the return
/// representation is an internal type exposed only through the trait.
#[test]
fn test_redact_value_masks_all_text_and_option_input_shapes() {
    let masking = MaskingPolicy::default();
    let owned = String::from("raw-value");
    let borrowed = "raw-value";
    let cow: Cow<'_, str> = Cow::Owned(String::from("raw-value"));
    let optional_owned = Some(String::from("raw-value"));
    let optional_borrowed = Some("raw-value");
    let optional_cow = Some(Cow::Borrowed("raw-value"));

    assert_eq!(
        format!("{:?}", borrowed.redact_value(Sensitivity::High, &masking)),
        "\"****\""
    );
    assert_eq!(
        format!("{:?}", (&borrowed).redact_value(Sensitivity::High, &masking)),
        "\"****\""
    );
    assert_eq!(
        format!("{:?}", owned.redact_value(Sensitivity::High, &masking)),
        "\"****\""
    );
    assert_eq!(
        format!("{:?}", cow.redact_value(Sensitivity::High, &masking)),
        "\"****\""
    );
    assert_eq!(
        format!("{:?}", optional_owned.redact_value(Sensitivity::High, &masking)),
        "Some(\"****\")"
    );
    assert_eq!(
        format!("{:?}", optional_borrowed.redact_value(Sensitivity::High, &masking)),
        "Some(\"****\")"
    );
    assert_eq!(
        format!("{:?}", optional_cow.redact_value(Sensitivity::High, &masking)),
        "Some(\"****\")"
    );
}

/// Absent options stay absent and the lower policy levels still use their
/// configured edge-preserving algorithms.
#[test]
fn test_redact_value_preserves_absence_and_uses_requested_level() {
    let masking = MaskingPolicy::default();
    let absent: Option<String> = None;
    let absent_cow: Option<Cow<'_, str>> = None;
    let empty = "";
    let borrowed_cow = Cow::Borrowed("raw-value");

    assert_eq!(
        format!("{:?}", absent.redact_value(Sensitivity::Secret, &masking)),
        "None"
    );
    assert_eq!(
        format!("{:?}", absent_cow.redact_value(Sensitivity::Secret, &masking)),
        "None"
    );
    assert_eq!(
        format!("{:?}", empty.redact_value(Sensitivity::Secret, &masking)),
        "\"\""
    );
    assert_eq!(
        format!("{:?}", borrowed_cow.redact_value(Sensitivity::High, &masking)),
        "\"****\""
    );
    assert_eq!(
        format!("{:?}", "abcdefgh".redact_value(Sensitivity::Low, &masking)),
        "\"ab****gh\""
    );
    assert_eq!(
        format!("{:?}", "abcdefgh".redact_value(Sensitivity::Medium, &masking)),
        "\"*******h\""
    );
}

/// The hidden representation remains serializable without changing optional
/// shape when the serde feature is enabled.
#[cfg(feature = "serde")]
#[test]
fn test_redact_value_serialization_preserves_plain_and_option_shapes() {
    let masking = MaskingPolicy::default();
    let plain = "raw".redact_value(Sensitivity::Secret, &masking);
    let present = Some("raw").redact_value(Sensitivity::Secret, &masking);
    let absent: Option<&str> = None;
    let absent = absent.redact_value(Sensitivity::Secret, &masking);

    assert_eq!(
        serde_json::to_value(plain).expect("plain scalar should serialize"),
        serde_json::json!("<redacted>")
    );
    assert_eq!(
        serde_json::to_value(present).expect("present option should serialize"),
        serde_json::json!("<redacted>")
    );
    assert_eq!(
        serde_json::to_value(absent).expect("absent option should serialize"),
        serde_json::Value::Null
    );
}
