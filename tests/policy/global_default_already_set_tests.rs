// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`GlobalDefaultAlreadySet`](qubit_redact::GlobalDefaultAlreadySet).

use qubit_redact::GlobalDefaultAlreadySet;

/// Verifies the global-default installation error has a stable message.
#[test]
fn test_global_default_already_set_display_is_descriptive() {
    assert_eq!(
        GlobalDefaultAlreadySet.to_string(),
        "the requested global redaction default is already set",
    );
}
