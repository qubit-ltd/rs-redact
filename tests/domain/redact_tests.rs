// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the [`Redact`](qubit_redact::domain::Redact) domain contract.

use qubit_redact::domain::Redact;
use qubit_redact::domain::RedactionWriter;
/// Minimal domain value used to verify the borrowed redacted view contract.
struct TestDomainValue;

impl Redact for TestDomainValue {
    /// Writes a fixed redacted representation without consulting source data.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.literal("TestDomainValue { secret: <redacted> }");
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
