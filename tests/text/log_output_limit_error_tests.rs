// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`LogOutputLimitError`](qubit_redact::LogOutputLimitError).

use qubit_redact::LogOutputLimit;

/// Verifies an undersized budget reports both requested and minimum bytes.
#[test]
fn test_log_output_limit_error_describes_invalid_budget() {
    let requested = LogOutputLimit::MINIMUM - 1;
    let error =
        LogOutputLimit::new(requested).expect_err("a budget below the marker length must fail");

    assert_eq!(error.requested(), requested);
    assert_eq!(error.minimum(), LogOutputLimit::MINIMUM);
    assert_eq!(
        error.to_string(),
        format!(
            "log output limit {requested} bytes is smaller than the minimum {} bytes",
            LogOutputLimit::MINIMUM,
        ),
    );
}
