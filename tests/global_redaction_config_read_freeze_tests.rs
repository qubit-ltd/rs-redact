// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression test for first-read global configuration freezing.

use qubit_redact::{
    GlobalRedactionConfig,
    GlobalRedactionConfigAlreadyInstalled,
    RedactionPolicy,
};

/// Verifies a first default read freezes the same global slot used by install.
#[test]
fn test_current_freezes_standard_config_before_late_install() {
    let before = GlobalRedactionConfig::current().clone();

    let result =
        GlobalRedactionConfig::from_policy(RedactionPolicy::strict()).install();

    assert_eq!(result, Err(GlobalRedactionConfigAlreadyInstalled));
    assert_eq!(GlobalRedactionConfig::current(), &before);
}
