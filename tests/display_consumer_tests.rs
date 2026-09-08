// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Explicit third-party Display adaptation is lazy and policy-aware.
#![cfg(feature = "derive")]

use std::cell::Cell;
use std::fmt;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;

struct External<'a> {
    calls: &'a Cell<usize>,
}

impl fmt::Display for External<'_> {
    /// Records a call and writes a fixed payload; propagates formatter errors.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.calls.set(self.calls.get() + 1);
        f.write_str("abcdef")
    }
}

#[derive(Redact)]
#[cfg_attr(feature = "serde", redact(serde))]
struct Secret<T> {
    #[redact(level = "secret", display)]
    value: T,
}

#[derive(Redact)]
#[cfg_attr(feature = "serde", redact(serde))]
struct Low<T> {
    #[redact(display, level = "low")]
    value: T,
}

/// Opaque masks avoid Display, while disabled output calls it once per
/// execution.
#[test]
fn test_display_is_not_called_for_opaque_masks() {
    let calls = Cell::new(0);
    let value = Secret {
        value: External { calls: &calls },
    };
    assert!(
        Redactor::standard()
            .redact_text(&value)
            .text()
            .as_str()
            .contains("<redacted>")
    );
    assert_eq!(calls.get(), 0);
    #[cfg(feature = "json")]
    {
        assert_eq!(
            Redactor::standard().to_json(&value).expect("opaque JSON"),
            r#"{"value":"<redacted>"}"#
        );
        assert_eq!(calls.get(), 0);
    }
    let disabled = Redactor::new(RedactionPolicy::disabled());
    assert!(disabled.redact_text(&value).text().as_str().contains("abcdef"));
    assert_eq!(calls.get(), 1);
    #[cfg(feature = "json")]
    {
        assert_eq!(
            disabled.to_json(&value).expect("Display string JSON"),
            r#"{"value":"abcdef"}"#
        );
        assert_eq!(calls.get(), 2);
    }
}

/// An explicit Low level remains final under the strict runtime policy.
#[test]
fn test_display_low_level_is_final_even_under_strict_policy() {
    let calls = Cell::new(0);
    let value = Low {
        value: External { calls: &calls },
    };
    assert!(
        Redactor::strict()
            .redact_text(&value)
            .text()
            .as_str()
            .contains("ab****ef")
    );
    assert_eq!(calls.get(), 1);
}

/// Rejected Display input produces a safe replacement within the configured
/// budget.
#[test]
fn test_display_respects_input_budget_without_unbounded_capture() {
    let calls = Cell::new(0);
    let value = Low {
        value: External { calls: &calls },
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);
    let output = redactor.redact_text(&value);
    assert!(!output.text().as_str().contains("abcdef"));
    #[cfg(feature = "json")]
    {
        let json = redactor.to_json(&value).expect("bounded replacement");
        assert_eq!(json, r#"{"value":"<redacted>"}"#);
    }
}

/// One-shot and batch paths reject oversized keys before accessing the value.
#[test]
fn test_scalar_field_admits_key_and_input_before_rendering() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(1);
            limits.max_key_bytes(1);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);
    let direct = redactor.redact_field("oversized_key", "visible-value");
    assert!(!direct.text().as_str().contains("visible-value"));
    assert!(
        direct
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_field("oversized_key", "visible-value");
    let diagnostics = batch.finish_with_marker("<redaction incomplete>");
    assert_eq!(diagnostics.text(handle).as_str(), "<redaction incomplete>");
}
