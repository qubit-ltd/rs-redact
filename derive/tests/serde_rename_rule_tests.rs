// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for Serde rename-rule application.

mod support;

/// Verifies representation names remain stable through serialization.
#[test]
fn test_serde_rename_rule_preserves_configured_names() {
    support::assertions::assert_serde_expansion();
}
