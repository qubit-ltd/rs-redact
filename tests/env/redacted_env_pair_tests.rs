// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use qubit_redact::Redactor;

/// Verifies that a non-sensitive environment pair remains visible only after
/// its one-shot transaction has completed.
#[test]
fn test_redactor_redact_env_returns_completed_safe_assignment() {
    let output = Redactor::standard().redact_env("MODE", "debug");

    assert_eq!(output.text().as_str(), "MODE=debug");
}
