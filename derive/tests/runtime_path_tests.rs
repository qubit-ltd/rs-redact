// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for runtime path resolution.

mod support;

/// Verifies the ordinary direct runtime dependency resolves in expansion.
#[test]
fn test_runtime_path_resolves_direct_dependency() {
    support::assertions::assert_named_redaction();
}
