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
fn test_fallback_global_read_does_not_block_later_installation() {
    let before_global = RedactionPolicy::global().clone();
    let before_default = RedactionPolicy::default();
    let before_builder = RedactionPolicy::builder_from_default();

    RedactionPolicy::install_global(RedactionPolicy::strict())
        .expect("a fallback read must not occupy the global policy slot");

    assert_eq!(before_global, RedactionPolicy::standard());
    assert_eq!(before_default, RedactionPolicy::standard());
    assert_eq!(
        before_builder
            .build()
            .expect("the pre-install default builder should remain valid"),
        RedactionPolicy::standard(),
    );
    assert_eq!(RedactionPolicy::global(), &RedactionPolicy::strict());
    assert_eq!(RedactionPolicy::default(), RedactionPolicy::strict());
    assert_eq!(
        RedactionPolicy::builder_from_default()
            .build()
            .expect("the post-install default builder should remain valid"),
        RedactionPolicy::strict(),
    );
}
