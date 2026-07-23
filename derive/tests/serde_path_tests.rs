// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for direct Serde path resolution.

mod support;

/// Verifies the direct Serde dependency is usable by generated code.
#[test]
fn test_serde_path_resolves_direct_dependency() {
    support::assertions::assert_serde_expansion();
}
