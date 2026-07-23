// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use qubit_redact::Redactor;

/// Verifies that the private serde support boundary does not affect core
/// redaction.
#[test]
fn test_private_support_keeps_core_redaction_available() {
    assert_eq!(
        Redactor::default().redact("password", "raw").as_str(),
        "<redacted>",
    );
}
