// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedText`](qubit_redact::RedactedText).

use qubit_redact::Redactor;
/// Verifies redacted text exposes the masked scalar value.
#[test]
fn test_redacted_text_exposes_masked_value() {
    let text = Redactor::default().redact_field("password", "raw");

    assert_eq!(text.text().as_str(), "<redacted>");
}

/// Verifies final text supports the ordinary string-facing boundary without
/// exposing an unredacted representation.
#[test]
fn test_redacted_text_supports_display_borrow_and_owned_conversion() {
    let text = Redactor::default().redact_field("message", "visible");
    let final_text = text
        .into_complete_text()
        .expect("field output must be complete");

    assert_eq!(final_text.as_ref(), "visible");
    assert_eq!(final_text.to_string(), "visible");
    assert_eq!(final_text.into_string(), "visible");
}
