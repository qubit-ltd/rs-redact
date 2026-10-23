// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public contracts for non-rendering redaction inspection.

use std::fmt;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

/// A value whose formatter proves inspection never renders field contents.
struct PanicOnDebug;

impl fmt::Debug for PanicOnDebug {
    /// Panics whenever production code incorrectly attempts to render it.
    fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("inspection must not format field values")
    }
}

/// A domain value containing explicit plain and sensitive declarations.
struct InspectedDomainValue {
    plain: PanicOnDebug,
    low: PanicOnDebug,
    secret: PanicOnDebug,
}

impl Redact for InspectedDomainValue {
    /// Declares the domain structure through the public redaction writer.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("InspectedDomainValue", |fields| {
            let _ = fields.unredacted("plain", || &self.plain);
            let _ = fields.sensitive_at_least(Sensitivity::Low, "low", || &self.low);
            let _ = fields.sensitive_at_least(Sensitivity::Secret, "secret", || &self.secret);
        });
    }
}

/// Verifies generic inspection aggregates sensitivity without rendering data.
#[test]
fn test_inspect_domain_value_reports_highest_sensitivity_without_formatting() {
    let value = InspectedDomainValue {
        plain: PanicOnDebug,
        low: PanicOnDebug,
        secret: PanicOnDebug,
    };
    let redactor = Redactor::standard();

    let direct = redactor.inspect(&value).expect("inspection should complete");
    assert!(
        direct.contains_sensitive(),
        "declared sensitive fields should be reported"
    );
    assert_eq!(
        direct.max_sensitivity(),
        Some(Sensitivity::Secret),
        "inspection should report the highest declared sensitivity"
    );
    assert_eq!(
        direct.usage().output_bytes(),
        0,
        "inspection should not render field contents"
    );
}

/// Verifies an explicitly plain domain object produces a conclusive clear
/// result.
#[test]
fn test_inspect_plain_domain_value_reports_no_sensitivity() {
    struct PlainValue(PanicOnDebug);

    impl Redact for PlainValue {
        /// Declares the only field as intentionally unredacted.
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("PlainValue", |fields| {
                let _ = fields.unredacted("value", || &self.0);
            });
        }
    }

    let inspection = Redactor::strict()
        .inspect(&PlainValue(PanicOnDebug))
        .expect("plain inspection should complete");

    assert!(
        !inspection.contains_sensitive(),
        "an explicitly plain value should not report sensitive fields"
    );
    assert_eq!(
        inspection.max_sensitivity(),
        None,
        "an explicitly plain value should have no maximum sensitivity"
    );
    assert_eq!(
        inspection.usage().output_bytes(),
        0,
        "inspection should not render field contents"
    );
}

#[test]
fn test_inspection_queries_report_sensitive_and_disabled_states() {
    let sensitive = Redactor::strict()
        .inspect_field("password", "raw-secret")
        .expect("strict scalar inspection should complete");
    assert!(sensitive.contains_sensitive());
    assert!(!sensitive.is_redaction_disabled());
    assert_eq!(sensitive.max_sensitivity(), Some(Sensitivity::Secret));

    let disabled = Redactor::new(RedactionPolicy::disabled())
        .inspect_field("password", "raw-secret")
        .expect("disabled scalar inspection should complete");
    assert!(!disabled.contains_sensitive());
    assert!(disabled.is_redaction_disabled());
    assert_eq!(disabled.max_sensitivity(), None);
}

/// An incomplete traversal is never published as a conclusive inspection.
#[test]
fn test_inspect_domain_value_fails_closed_at_structural_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let value = InspectedDomainValue {
        plain: PanicOnDebug,
        low: PanicOnDebug,
        secret: PanicOnDebug,
    };

    let error = Redactor::new(policy)
        .inspect(&value)
        .expect_err("limited traversal must be inconclusive");

    assert!(
        error.reasons().contains(RedactionReason::TraversalLimitReached),
        "limited traversal should report that the traversal limit was reached"
    );
    assert_eq!(
        error.usage().output_bytes(),
        0,
        "failed inspection should not render field contents"
    );
}

/// Verifies public inspection queries distinguish sensitive and disabled
/// states.
#[test]
fn test_inspection_queries_report_sensitive_and_disabled_states_with_standard_policy() {
    let sensitive = Redactor::standard()
        .inspect_field("password", "secret")
        .expect("inspection should complete");
    assert!(sensitive.contains_sensitive());
    assert!(!sensitive.is_redaction_disabled());
    assert_eq!(sensitive.max_sensitivity(), Some(Sensitivity::Secret));

    let disabled = Redactor::new(RedactionPolicy::disabled())
        .inspect_field("password", "secret")
        .expect("disabled inspection should complete");
    assert!(!disabled.contains_sensitive());
    assert!(disabled.is_redaction_disabled());
    assert_eq!(disabled.max_sensitivity(), None);
}
