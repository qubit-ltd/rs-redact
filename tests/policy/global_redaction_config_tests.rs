// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the global redaction configuration error.

use qubit_redact::GlobalRedactionConfigAlreadyInstalled;

/// Verifies the one-time installation error has a descriptive message.
#[test]
fn test_global_config_already_installed_display_is_descriptive() {
    assert_eq!(
        GlobalRedactionConfigAlreadyInstalled.to_string(),
        "the global redaction configuration is already installed",
    );
}
