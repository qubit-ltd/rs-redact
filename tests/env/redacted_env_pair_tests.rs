// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use qubit_redact::formats::env::EnvRedactor;
/// Verifies that a redacted environment pair is displayable.
#[test]
fn test_redacted_env_pair_displays_assignment() {
    assert_eq!(
        EnvRedactor::default()
            .redact_pair("MODE", "debug")
            .to_string(),
        "MODE=debug"
    );
}
