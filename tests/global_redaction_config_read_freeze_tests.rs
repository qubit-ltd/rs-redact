// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression test for first-read global configuration freezing.

use qubit_redact::RedactionPolicy;

/// Verifies a first default read freezes the same global slot used by install.
#[test]
fn test_current_freezes_standard_config_before_late_install() {
    let before = RedactionPolicy::global().clone();

    let result = RedactionPolicy::install_global(RedactionPolicy::strict());

    assert!(result.is_err());
    assert_eq!(RedactionPolicy::global(), &before);
}
