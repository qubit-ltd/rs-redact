// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI redaction reason values.

use qubit_redact::UriComponent;
use qubit_redact::UriRedactionReason;
/// Verifies sensitive component reasons carry their component identity.
#[test]
fn test_uri_reason_identifies_sensitive_component() {
    assert_eq!(
        UriRedactionReason::SensitiveComponent(UriComponent::Password),
        UriRedactionReason::SensitiveComponent(UriComponent::Password),
    );
}
