// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Crate-internal diagnostics for redaction handle resolution.

use crate::facade::DiagnosticRedactionHandleError;

/// Both lookup failures expose stable, value-free diagnostics.
#[test]
fn test_diagnostic_handle_error_display() {
    assert_eq!(
        DiagnosticRedactionHandleError::DifferentBatch.to_string(),
        "the handle belongs to a different batch"
    );
    assert_eq!(
        DiagnosticRedactionHandleError::MissingItem.to_string(),
        "the handle does not identify a published item"
    );
}
