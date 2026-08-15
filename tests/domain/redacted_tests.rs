// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for non-destructive redacted views.

use std::fmt;

use qubit_redact::InputOutputLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::Redact;
use qubit_redact::RedactValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
use qubit_redact::Sensitivity;
use qubit_redact::domain::DomainTruncated;
#[cfg(feature = "serde")]
use qubit_redact::domain::RedactSerialize;
use qubit_redact::policy::DomainTraversalAdmission;
use qubit_redact::policy::DomainValueAdmission;
#[cfg(feature = "serde")]
use serde::Serializer;
#[cfg(feature = "serde")]
use serde_json::to_value;

/// Account whose manual implementation follows incremental domain admission.
struct IncrementalManualAccount {
    /// Public user name that remains visible.
    user: String,
    /// Secret credential that must never be inspected while formatting.
    password: String,
}

impl Redact for IncrementalManualAccount {
    /// Formats admitted fields and replaces the password with a fixed value.
    fn fmt_redacted(
        &self,
        session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let DomainValueAdmission::Entered(mut scope) =
            session.enter_domain_value()
        else {
            return formatter.write_str("<truncated>");
        };
        let mut output = formatter.debug_struct("ManualAccount");
        if scope.admit_field() == DomainTraversalAdmission::LimitReached {
            return output.field("user", &DomainTruncated).finish();
        }
        output.field("user", &self.user);
        if scope.admit_field() == DomainTraversalAdmission::LimitReached {
            return output.field("password", &DomainTruncated).finish();
        }
        output.field("password", &"<redacted>").finish()
    }
}

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
        session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let DomainValueAdmission::Entered(mut scope) =
            session.enter_domain_value()
        else {
            return fmt::Debug::fmt(&DomainTruncated, formatter);
        };
        let mut output = formatter.debug_struct("ManualAccount");
        if scope.admit_field() == DomainTraversalAdmission::LimitReached {
            return output.field("id", &DomainTruncated).finish();
        }
        output.field("id", &self.id);
        if scope.admit_field() == DomainTraversalAdmission::LimitReached {
            return output.field("password", &DomainTruncated).finish();
        }
        output.field(
            "password",
            &self.password.redact_value(
                Sensitivity::Secret,
                scope.session().policy().masking(),
            ),
        );
        if scope.admit_field() == DomainTraversalAdmission::LimitReached {
            return output.field("note", &DomainTruncated).finish();
        }
        output.field("note", &self.note).finish()
    }
}

/// Verifies manual domain formatting does not require an input-byte forecast.
#[test]
fn test_manual_redact_without_input_forecast_formats_safe_structure() {
    let account = IncrementalManualAccount {
        user: "ada".to_owned(),
        password: "raw-secret".to_owned(),
    };

    assert_eq!(
        format!("{:?}", account.redacted()),
        r#"ManualAccount { user: "ada", password: "<redacted>" }"#,
    );
    assert_eq!(account.password, "raw-secret");
}

#[cfg(feature = "serde")]
impl RedactSerialize for ManualAccount {
    /// Serializes the same masked account value through the serde hook.
    fn serialize_redacted<S>(
        &self,
        policy: &RedactionPolicy,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ManualAccount", 3)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field(
            "password",
            &self
                .password
                .redact_value(Sensitivity::Secret, policy.masking()),
        )?;
        state.serialize_field("note", &self.note)?;
        state.end()
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

/// Verifies ordinary debug formatting uses the policy diagnostic output limit.
#[test]
fn test_redacted_debug_uses_policy_output_limit_by_default() {
    let account = ManualAccount {
        id: 12,
        password: "raw-secret".to_owned(),
        note: "visible diagnostic text".to_owned(),
    };
    let budget =
        InputOutputLimit::new(1024, InputOutputLimit::MIN_OUTPUT_BYTES)
            .expect("the minimum diagnostic output limit should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the diagnostic budget should build a policy");

    let output = format!("{:?}", account.redacted_with(&policy));

    assert!(output.len() <= budget.max_output_bytes());
    assert!(output.ends_with("<truncated>"));
}

/// Verifies display uses the policy output budget by default.
#[test]
fn test_redacted_display_uses_policy_output_limit_by_default() {
    let account = ManualAccount {
        id: 12,
        password: "raw-secret".to_owned(),
        note: "visible diagnostic text".to_owned(),
    };
    let budget =
        InputOutputLimit::new(1024, InputOutputLimit::MIN_OUTPUT_BYTES)
            .expect("the minimum bounded output should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the diagnostic budget should build a policy");

    let output = account.redacted_with(&policy).to_string();

    assert!(output.len() <= budget.max_output_bytes());
    assert!(output.ends_with("<truncated>"));
}

#[cfg(feature = "serde")]
#[test]
fn test_redacted_view_serializes_through_the_explicit_policy() {
    let account = ManualAccount {
        id: 13,
        password: "raw-secret".to_owned(),
        note: "visible".to_owned(),
    };
    let policy = RedactionPolicy::builder()
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[serde]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the fixed masking policy should build");

    let serialized = to_value(account.redacted_with(&policy))
        .expect("the redacted view should serialize");

    assert_eq!(serialized["id"], 13);
    assert_eq!(serialized["password"], "[serde]");
    assert_eq!(serialized["note"], "visible");
}
