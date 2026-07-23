// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use qubit_redact::EnvRedactor;

/// Verifies that environment redaction masks a password value.
#[test]
fn test_env_redactor_masks_password_value() {
    assert_eq!(
        EnvRedactor::default()
            .redact_pair("PASSWORD", "raw")
            .to_string(),
        "PASSWORD=<redacted>"
    );
}
