// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodyCaptureError`](qubit_redact::formats::http::BodyCaptureError).

use qubit_redact::formats::http::BodyCaptureError;
/// Verifies invalid source-length metadata has a stable error message.
#[test]
fn test_body_capture_error_describes_invalid_total_length() {
    assert_eq!(
        BodyCaptureError::InvalidTotalLength { captured: 4, total: 4 }.to_string(),
        "truncated body total length 4 must exceed 4 captured bytes",
    );
}
