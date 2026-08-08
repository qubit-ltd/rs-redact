// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use qubit_redact::Redactor;
/// Verifies that core redaction remains available through feature selection.
#[test]
fn test_serde_feature_gate_keeps_core_redaction_available() {
    assert_eq!(
        Redactor::default().redact_field("password", "raw").as_str(),
        "<redacted>",
    );
}
