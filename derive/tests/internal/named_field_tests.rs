// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for parsed named-field state.

use crate::support;

/// Verifies parsed named fields retain names and controls.
#[test]
fn test_named_field_retains_name_and_controls() {
    support::assertions::assert_named_redaction();
}
