// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`NameMatchMode`](qubit_sanitize::NameMatchMode).

use qubit_sanitize::NameMatchMode;

#[test]
fn test_name_match_modes_are_distinct() {
    assert_ne!(NameMatchMode::Exact, NameMatchMode::ExactOrSuffix);
}
