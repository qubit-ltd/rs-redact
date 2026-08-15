// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI component classification.

use qubit_redact::uri::UriComponent;
/// Verifies URI components remain distinct and copyable.
#[test]
fn test_uri_components_are_distinct() {
    assert_ne!(UriComponent::Username, UriComponent::Password);
    assert_ne!(UriComponent::Query, UriComponent::Path);
}
