// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the [`Redact`](qubit_redact::Redact) domain contract.

use std::fmt;

use qubit_redact::{
    Redact,
    RedactionPolicy,
};

/// Minimal domain value used to verify the borrowed redacted view contract.
struct TestDomainValue;

impl Redact for TestDomainValue {
    /// Writes a fixed redacted representation without consulting source data.
    fn fmt_redacted(
        &self,
        _policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str("TestDomainValue { secret: <redacted> }")
    }
}

/// Verifies that the trait creates a displayable redacted view.
#[test]
fn test_redact_redacted_formats_custom_domain_value() {
    assert_eq!(
        TestDomainValue.redacted().to_string(),
        "TestDomainValue { secret: <redacted> }",
    );
}
