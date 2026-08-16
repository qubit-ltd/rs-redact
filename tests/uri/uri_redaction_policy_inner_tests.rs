// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI policy snapshot isolation.

use qubit_redact::RedactionPolicy;
use qubit_redact::formats::uri::UriFragmentPolicy;
use qubit_redact::formats::uri::UriPathPolicy;
/// Verifies URI policy snapshots retain their own immutable behavior state.
#[test]
fn test_uri_policy_inner_keeps_built_snapshot_immutable() {
    let base = RedactionPolicy::default();
    let mut builder = base.to_builder();
    builder.uri().path(UriPathPolicy::Redact);
    builder.uri().fragment(UriFragmentPolicy::Preserve);
    let configured = builder
        .build()
        .expect("the configured policy must be valid");

    assert_eq!(base.uri().path_policy(), UriPathPolicy::Preserve);
    assert_eq!(base.uri().fragment_policy(), UriFragmentPolicy::Redact);
    assert_eq!(configured.uri().path_policy(), UriPathPolicy::Redact);
    assert_eq!(
        configured.uri().fragment_policy(),
        UriFragmentPolicy::Preserve
    );
}
