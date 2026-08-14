// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the runtime diagnostic budget used by redaction sessions.

use qubit_redact::Redactor;

/// Verifies a new session starts with its configured input allowance.
#[test]
fn test_runtime_budget_starts_with_configured_input() {
    let redactor = Redactor::default();
    let session = redactor.session();

    assert_eq!(session.remaining_input_bytes(), 16 * 1024);
}
