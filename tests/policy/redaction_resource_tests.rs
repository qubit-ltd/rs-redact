// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for resource accounting used by bounded redaction.

use qubit_redact::Redactor;

/// Verifies resource-backed session accounting exposes the configured budget.
#[test]
fn test_resource_accounting_is_initialized_for_a_session() {
    let redactor = Redactor::default();
    let session = redactor.session();

    assert!(!session.is_exhausted());
}
