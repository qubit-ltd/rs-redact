// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for non-destructive redacted views.

use std::fmt;

use qubit_redact::{
    DiagnosticBudget,
    MaskPolicy,
    Redact,
    RedactValue,
    RedactionPolicy,
    Sensitivity,
};

/// Account with a manually implemented redacted representation.
struct ManualAccount {
    /// Public identifier that remains visible.
    id: u64,
    /// Secret credential that must be masked.
    password: String,
    /// Diagnostic note whose controls must be escaped for display.
    note: String,
}

impl Redact for ManualAccount {
    /// Formats the account while masking its password.
    fn fmt_redacted(
        &self,
        policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter
            .debug_struct("ManualAccount")
            .field("id", &self.id)
            .field(
                "password",
                &self
                    .password
                    .redact_value(Sensitivity::Secret, policy.masking()),
            )
            .field("note", &self.note)
            .finish()
    }
}

/// Verifies that redacted views do not modify their source and that display is
/// safe for a single-line log boundary.
#[test]
fn test_redacted_view_is_non_destructive_and_display_is_log_safe() {
    let account = ManualAccount {
        id: 7,
        password: "raw-secret".to_owned(),
        note: "line-one\nline-two".to_owned(),
    };

    let debug = format!("{:?}", account.redacted());
    let display = account.redacted().to_string();

    assert!(!debug.contains("raw-secret"));
    assert!(!display.contains("raw-secret"));
    assert!(!display.contains('\n'));
    assert!(display.contains(r"\n"));
    assert_eq!(account.password, "raw-secret");
}

/// Verifies that a view owns a stable snapshot of its caller-supplied policy.
#[test]
fn test_redacted_with_snapshots_policy() {
    let account = ManualAccount {
        id: 9,
        password: "raw-secret".to_owned(),
        note: "visible".to_owned(),
    };
    let view = {
        let policy = RedactionPolicy::builder()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[snapshot]"))
            .expect("the test mask policy should be valid")
            .build()
            .expect("the fixed masking policy should be valid");
        account.redacted_with(&policy)
    };

    assert_eq!(
        format!("{view:?}"),
        "ManualAccount { id: 9, password: \"[snapshot]\", note: \"visible\" }",
    );
}

/// Verifies that redacted debug preserves the formatter's alternate pretty
/// flag while display escapes the resulting line breaks.
#[test]
fn test_redacted_debug_preserves_pretty_flag() {
    let account = ManualAccount {
        id: 11,
        password: "raw-secret".to_owned(),
        note: "visible".to_owned(),
    };

    let pretty = format!("{:#?}", account.redacted());
    let display = format!("{}", account.redacted());

    assert_eq!(
        pretty,
        "ManualAccount {\n    id: 11,\n    password: \"<redacted>\",\n    note: \"visible\",\n}",
    );
    assert!(!display.contains('\n'));
}

/// Verifies a view can derive its output bound from its policy snapshot.
#[test]
fn test_redacted_with_policy_output_limit_uses_policy_budget() {
    let account = ManualAccount {
        id: 12,
        password: "raw-secret".to_owned(),
        note: "visible diagnostic text".to_owned(),
    };
    let budget =
        DiagnosticBudget::new(1024, DiagnosticBudget::MIN_OUTPUT_BYTES)
            .expect("the minimum bounded output should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_budget(budget)
        .build()
        .expect("the diagnostic budget should build a policy");

    let output = account
        .redacted_with(&policy)
        .with_policy_output_limit()
        .to_string();

    assert!(output.len() <= budget.max_output_bytes());
    assert!(output.ends_with("<truncated>"));
}
