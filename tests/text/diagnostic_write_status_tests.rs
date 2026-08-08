// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`DiagnosticWriteStatus`](qubit_redact::DiagnosticWriteStatus).

use qubit_redact::DiagnosticLogBuilder;
use qubit_redact::DiagnosticWriteStatus;
use qubit_redact::InputOutputLimit;
/// Verifies a fragment that fits reports completion.
#[test]
fn test_diagnostic_write_status_reports_complete_fragment() {
    let budget =
        InputOutputLimit::new(128, 64).expect("the test budget is valid");
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder.push_fmt(format_args!("short message")),
        Ok(DiagnosticWriteStatus::Complete),
    );
}

/// Verifies a fragment beyond the output budget reports truncation.
#[test]
fn test_diagnostic_write_status_reports_truncated_fragment() {
    let budget = InputOutputLimit::new(128, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the test budget is valid");
    let mut builder = DiagnosticLogBuilder::new(budget);

    assert_eq!(
        builder.push_fmt(format_args!(
            "payload that cannot fit and is definitely longer than the marker"
        )),
        Ok(DiagnosticWriteStatus::Truncated),
    );
    assert!(builder.is_truncated());
}
