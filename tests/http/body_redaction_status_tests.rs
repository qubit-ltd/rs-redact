// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BodyRedactionStatus`](qubit_redact::http::BodyRedactionStatus).

use qubit_redact::http::BodyRedactionReason;
use qubit_redact::http::BodyRedactionStatus;
/// Verifies a fail-closed status retains its precise reason.
#[test]
fn test_body_redaction_status_retains_reason() {
    assert_eq!(
        BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson),
        BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson),
    );
}
