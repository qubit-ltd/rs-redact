// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactValueMut`](qubit_redact::RedactValueMut).

use std::borrow::Cow;

use qubit_redact::MaskingPolicy;
use qubit_redact::RedactValueMut;
use qubit_redact::Sensitivity;
/// Verifies in-place scalar redaction replaces an owned secret value.
#[test]
fn test_redact_value_mut_replaces_owned_string() {
    let mut value = String::from("raw");
    value.redact_value_in_place(Sensitivity::Secret, &MaskingPolicy::default());

    assert_eq!(value, "<redacted>");
}

/// Verifies borrowed and absent values remain unchanged when masking borrows.
#[test]
fn test_redact_value_mut_preserves_empty_and_absent_values() {
    let mut text = String::new();
    let mut cow = Cow::Borrowed("");
    let mut absent: Option<String> = None;
    let masking = MaskingPolicy::default();

    text.redact_value_in_place(Sensitivity::Secret, &masking);
    cow.redact_value_in_place(Sensitivity::Secret, &masking);
    absent.redact_value_in_place(Sensitivity::Secret, &masking);

    assert!(text.is_empty());
    assert!(cow.is_empty());
    assert!(absent.is_none());
}
