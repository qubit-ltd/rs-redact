// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for Serde enum representation selection.

mod support;

/// Verifies an adjacent representation emits separate tag and content.
#[test]
fn test_serde_enum_representation_emits_tag_and_content() {
    support::assertions::assert_serde_expansion();
}
