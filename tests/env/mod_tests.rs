// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public environment module boundary.

use qubit_redact::formats::env::EnvRedactor;
/// Verifies the module exposes a complete assignment redaction path.
#[test]
fn test_env_module_reexports_compose() {
    let rendered = EnvRedactor::default()
        .redact_assignment("PASSWORD=raw-secret")
        .to_string();

    assert!(!rendered.contains("raw-secret"));
}
