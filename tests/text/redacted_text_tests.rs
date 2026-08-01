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

    assert_eq!(text.as_str(), "<redacted>");
}
