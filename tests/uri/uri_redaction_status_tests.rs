// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI redaction status values.

use qubit_redact::UriRedactionStatus;

/// Verifies a new status defaults to pass-through.
#[test]
fn test_uri_redaction_status_defaults_to_passed_through() {
    assert_eq!(
        UriRedactionStatus::PassedThrough,
        UriRedactionStatus::default(),
    );
}
