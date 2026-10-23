// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`PolicyLocation`](qubit_redact::PolicyLocation).

use qubit_redact::PolicyLocation;

/// Verifies each public policy context has a stable display label.
#[test]
fn test_policy_location_display_identifies_each_context() {
    assert_eq!(PolicyLocation::Rules.to_string(), "rules");
    assert_eq!(PolicyLocation::Floor.to_string(), "floor");
    assert_eq!(PolicyLocation::HttpHeader.to_string(), "http header");
    assert_eq!(PolicyLocation::HttpQuery.to_string(), "http query");
    assert_eq!(PolicyLocation::HttpBody.to_string(), "http body");
    assert_eq!(PolicyLocation::HttpMasking.to_string(), "http masking");
}
