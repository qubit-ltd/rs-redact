// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for shared HTTP diagnostic budget helpers.

use qubit_redact::{
    RedactionPolicy,
    http::{
        HttpRedactor,
        InputOutputLimit,
    },
};

/// Verifies diagnostic input limits return the fixed safe marker.
#[test]
fn test_diagnostic_input_limit_returns_fixed_marker() {
    let budget = InputOutputLimit::new(16, 128)
        .expect("test diagnostic budget should satisfy minimums");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("HTTP policy should be valid");
    let redactor = HttpRedactor::new(policy);

    assert_eq!(
        redactor
            .redact_url_str("https://example.test/?password=secret")
            .as_ref(),
        "<redacted: diagnostic limit exceeded>",
    );
}
