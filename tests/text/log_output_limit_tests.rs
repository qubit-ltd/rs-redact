// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`LogOutputLimit`](qubit_redact::LogOutputLimit).

use qubit_redact::LogOutputLimit;

/// Verifies a valid limit preserves its configured byte count.
#[test]
fn test_log_output_limit_preserves_valid_budget() {
    let limit = LogOutputLimit::new(256)
        .expect("the limit can contain the truncation marker");

    assert_eq!(limit.max_bytes(), 256);
}

/// Verifies the smallest accepted limit can contain exactly the marker.
#[test]
fn test_log_output_limit_accepts_minimum_budget() {
    let limit = LogOutputLimit::new(LogOutputLimit::MINIMUM)
        .expect("the minimum limit is valid");

    assert_eq!(limit.max_bytes(), LogOutputLimit::MINIMUM);
}
