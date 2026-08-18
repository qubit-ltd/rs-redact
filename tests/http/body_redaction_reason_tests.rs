// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodyRedactionReason`](qubit_redact::formats::http::BodyRedactionReason).

use qubit_redact::formats::http::BodyRedactionReason;
/// Verifies the opaque-text reason is available to callers.
#[test]
fn test_body_redaction_reason_exposes_opaque_text_variant() {
    assert_eq!(BodyRedactionReason::OpaqueText, BodyRedactionReason::OpaqueText,);
}

/// Verifies callers can distinguish shared-session exhaustion from media-type
/// dispatch failures.
#[test]
fn test_body_redaction_reason_exposes_diagnostic_budget_variant() {
    assert_eq!(
        BodyRedactionReason::DiagnosticBudgetExceeded,
        BodyRedactionReason::DiagnosticBudgetExceeded,
    );
}
