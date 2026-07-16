// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodyRedactionReason`](qubit_sanitize::BodyRedactionReason).

use qubit_sanitize::BodyRedactionReason;

#[test]
fn test_body_redaction_reason_supports_urlencoded_failures() {
    assert_ne!(
        BodyRedactionReason::InvalidFormUrlEncoded,
        BodyRedactionReason::InvalidOrTruncatedFormUrlEncoded,
    );
}
