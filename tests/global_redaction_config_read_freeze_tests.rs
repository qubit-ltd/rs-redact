// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression test for reading the fallback global configuration before setup.

use qubit_redact::RedactionPolicy;

/// Verifies a fallback read does not prevent the application from installing
/// its policy during later setup.
#[test]
fn test_fallback_read_does_not_block_later_installation() {
    let before = RedactionPolicy::global().clone();

    RedactionPolicy::install_global(RedactionPolicy::strict())
        .expect("a fallback read must not occupy the global policy slot");

    assert_eq!(before, RedactionPolicy::standard());
    assert_eq!(RedactionPolicy::global(), &RedactionPolicy::strict());
    assert_eq!(RedactionPolicy::default(), RedactionPolicy::strict());
}
