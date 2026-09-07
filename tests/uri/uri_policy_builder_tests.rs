// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI policy builder behavior.

use qubit_redact::RedactionPolicy;
use qubit_redact::formats::uri::UriFragmentPolicy;
use qubit_redact::formats::uri::UriPathPolicy;
/// Verifies the URI builder updates path and fragment choices independently.
#[test]
fn test_uri_policy_builder_updates_behavior_choices() {
    let policy = RedactionPolicy::default()
        .to_builder()
        .uri(|uri| {
            uri.path(UriPathPolicy::Redact).fragment(UriFragmentPolicy::Preserve);
        })
        .expect("the URI draft should be valid")
        .build()
        .expect("the configured policy must be valid");

    assert_eq!(policy.uri().path_policy(), UriPathPolicy::Redact);
    assert_eq!(policy.uri().fragment_policy(), UriFragmentPolicy::Preserve);
}
