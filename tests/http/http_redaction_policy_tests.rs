// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`HttpRedactionPolicy`](qubit_redact::http::HttpRedactionPolicy).

use qubit_redact::http::HttpRedactionPolicy;

/// Verifies the default HTTP policy has a non-zero body input budget.
#[test]
fn test_http_redaction_policy_default_has_input_budget() {
    assert!(
        HttpRedactionPolicy::default()
            .body_budget()
            .max_input_bytes()
            > 0
    );
}
