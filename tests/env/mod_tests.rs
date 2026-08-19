// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public environment module boundary.

use qubit_redact::Redactor;

/// Verifies the module exposes a complete assignment redaction path.
#[test]
fn test_environment_namespace_composes_with_a_transaction_session() {
    let mut session = Redactor::standard().session();
    let output = session
        .literal("environment: ")
        .env(|env| {
            env.pair("PASSWORD", "raw-secret");
        })
        .finish();

    assert_eq!(output.text().as_str(), "environment: PASSWORD=<redacted>");
}
