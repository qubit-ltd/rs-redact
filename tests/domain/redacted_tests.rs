// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for non-destructive redacted views.

use qubit_redact::InputOutputLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::domain::Redact;
#[cfg(feature = "serde")]
use qubit_redact::domain::RedactSerialize;
#[cfg(feature = "serde")]
use qubit_redact::domain::RedactValue;
use qubit_redact::domain::RedactionWriter;
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
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.record("ManualAccount", |fields| {
            fields.field("user", || &self.user);
            fields.field("password", || "<redacted>");
        });
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
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.record("ManualAccount", |fields| {
            fields.field("id", || self.id);
            fields
                .sensitive(Sensitivity::Secret, "password", || &self.password);
            fields.field("note", || &self.note);
        });
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
        let policy = ({
            let mut builder = RedactionPolicy::builder();
            builder
                .edit_fields()
                .mask(Sensitivity::Secret, MaskPolicy::fixed("[snapshot]"))
                .expect("the test mask policy should be valid");
            builder
        })
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
        "ManualAccount { id: 11, password: \"<redacted>\", note: \"visible\" }",
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
    let budget = InputOutputLimit::builder()
        .max_input_bytes(1024)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the minimum diagnostic output limit should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
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
    let budget = InputOutputLimit::builder()
        .max_input_bytes(1024)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the minimum bounded output should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .edit_fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[serde]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the fixed masking policy should build");

    let serialized = to_value(account.redacted_with(&policy))
        .expect("the redacted view should serialize");

    assert_eq!(serialized["id"], 13);
    assert_eq!(serialized["password"], "[serde]");
    assert_eq!(serialized["note"], "visible");
}
