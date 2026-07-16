// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodySanitizationStatus`](qubit_sanitize::BodySanitizationStatus).

use qubit_sanitize::{
    BodyRedactionReason,
    BodySanitizationStatus,
};

#[test]
fn test_body_sanitization_status_preserves_redaction_reason() {
    let status =
        BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidMultipart);

    assert_eq!(
        status,
        BodySanitizationStatus::Redacted(BodyRedactionReason::InvalidMultipart,),
    );
}
