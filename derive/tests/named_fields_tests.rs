// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for named-field parsing.

mod support;

/// Verifies named fields retain labels and explicit modes.
#[test]
fn test_named_fields_retain_labels_and_modes() {
    support::assertions::assert_named_redaction();
}
