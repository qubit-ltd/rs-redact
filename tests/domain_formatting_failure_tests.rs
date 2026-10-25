// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Domain formatter failures must be explicit and fail closed.

use std::cell::Cell;
use std::fmt;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

struct PartialDebug<'a>(&'a Cell<usize>);

impl fmt::Debug for PartialDebug<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        formatter.write_str("partial-debug-fragment")?;
        Err(fmt::Error)
    }
}

struct Payload<'a> {
    calls: &'a Cell<usize>,
    later_calls: &'a Cell<usize>,
    level: Option<Sensitivity>,
}

impl Redact for Payload<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Payload", |fields| {
            match self.level {
                Some(level) => {
                    fields.sensitive_at_least(level, "visible", || PartialDebug(self.calls));
                }
                None => {
                    fields.unredacted("visible", || PartialDebug(self.calls));
                }
            }
            fields.unredacted("later", || {
                self.later_calls.set(self.later_calls.get() + 1);
                "later-value"
            });
        });
    }
}

#[test]
fn test_formatter_error_is_a_failed_complete_scalar_and_rolls_back_text() {
    let calls = Cell::new(0);
    let later_calls = Cell::new(0);
    let output = Redactor::standard().redact_text(&Payload {
        calls: &calls,
        later_calls: &later_calls,
        level: None,
    });

    assert!(output.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert!(output.complete_text().is_err());
    assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(!output.text().as_str().contains("partial-debug-fragment"));
    assert!(output.text().as_str().contains("<formatting-failed>"));
    assert_eq!(calls.get(), 1);
    assert_eq!(later_calls.get(), 0);
}

#[test]
fn test_masked_formatter_error_stops_following_field_access() {
    for level in [Sensitivity::Low, Sensitivity::Medium] {
        let calls = Cell::new(0);
        let later_calls = Cell::new(0);
        let output = Redactor::standard().redact_text(&Payload {
            calls: &calls,
            later_calls: &later_calls,
            level: Some(level),
        });
        assert!(output.summary().reasons().contains(RedactionReason::FormattingFailed));
        assert!(!output.text().as_str().contains("partial-debug-fragment"));
        assert_eq!(calls.get(), 1);
        assert_eq!(later_calls.get(), 0);
    }
}

struct UnmarkedPayload<'a>(&'a Cell<usize>, &'a Cell<usize>);

impl Redact for UnmarkedPayload<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Payload", |fields| {
            fields.unmarked("visible", || PartialDebug(self.0));
            fields.unredacted("later", || {
                self.1.set(self.1.get() + 1);
                "later-value"
            });
        });
    }
}

#[test]
fn test_policy_classified_unmarked_field_propagates_debug_failure() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.low_sensitive("visible");
        })
        .expect("valid field rules")
        .build()
        .expect("valid policy");
    let calls = Cell::new(0);
    let later_calls = Cell::new(0);
    let output = Redactor::new(policy).redact_text(&UnmarkedPayload(&calls, &later_calls));
    assert!(output.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert_eq!(calls.get(), 1);
    assert_eq!(later_calls.get(), 0);
}

struct TinyFailure;

impl fmt::Debug for TinyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("x")?;
        Err(fmt::Error)
    }
}

struct TinyFailurePayload;

impl Redact for TinyFailurePayload {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Payload", |fields| {
            fields.unredacted("visible", || TinyFailure);
        });
    }
}

#[test]
fn test_formatting_failure_keeps_output_limit_when_its_marker_does_not_fit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(20);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let output = Redactor::new(policy).redact_text(&TinyFailurePayload);
    assert!(output.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(!output.text().as_str().contains('x'));
}

#[test]
fn test_opaque_high_sensitivity_does_not_call_source_debug() {
    for level in [Sensitivity::High, Sensitivity::Secret] {
        let calls = Cell::new(0);
        let value = OpaquePayloadWithLevel { calls: &calls, level };
        let output = Redactor::standard().redact_text(&value);
        assert!(output.complete_text().is_ok());
        assert_eq!(calls.get(), 0);
    }
}

struct OpaquePayloadWithLevel<'a> {
    calls: &'a Cell<usize>,
    level: Sensitivity,
}

impl Redact for OpaquePayloadWithLevel<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Payload", |fields| {
            fields.sensitive_at_least(self.level, "visible", || PartialDebug(self.calls));
        });
    }
}

struct ImmediateFailure;

impl fmt::Debug for ImmediateFailure {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Err(fmt::Error)
    }
}

struct ImmediateFailurePayload;

impl Redact for ImmediateFailurePayload {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Payload", |fields| {
            fields.sensitive_at_least(Sensitivity::Low, "visible", || ImmediateFailure);
        });
    }
}

#[test]
fn test_immediate_formatter_error_is_recorded() {
    let output = Redactor::standard().redact_text(&ImmediateFailurePayload);
    assert!(output.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert!(output.complete_text().is_err());
}

#[test]
fn test_composer_and_batch_report_domain_formatter_failure() {
    let calls = Cell::new(0);
    let later_calls = Cell::new(0);
    let value = Payload {
        calls: &calls,
        later_calls: &later_calls,
        level: None,
    };
    let composer = Redactor::standard().text_composer().value(&value).finish();
    assert!(composer.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert!(composer.complete_text().is_err());
    assert!(!composer.text().as_str().contains("partial-debug-fragment"));

    let mut batch = Redactor::standard().diagnostic_batch();
    let failed = batch.redact_value(&value);
    let calls_after_failure = calls.get();
    let safe = batch.redact_value(&SafeValue);
    let batch_output = batch.finish_with_marker("<incomplete>");
    assert!(
        batch_output
            .summary()
            .reasons()
            .contains(RedactionReason::FormattingFailed)
    );
    assert!(!batch_output.text(failed).as_str().contains("partial-debug-fragment"));
    assert!(batch_output.text(safe).as_str().contains("SafeValue"));
    assert_eq!(calls.get(), calls_after_failure);
}

struct SwallowsWriterError;

impl fmt::Debug for SwallowsWriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = formatter.write_str("this-fragment-is-deliberately-too-large");
        Ok(())
    }
}

struct OversizedPayload;

impl Redact for OversizedPayload {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Payload", |fields| {
            fields.unredacted("value", || SwallowsWriterError);
            fields.unredacted("later", || panic!("closed frame must not evaluate later fields"));
        });
    }
}

#[test]
fn test_swallowed_capacity_rejection_is_not_a_formatter_failure() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(32);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let output = Redactor::new(policy).redact_text(&OversizedPayload);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(!output.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert!(!output.text().as_str().contains("deliberately-too-large"));
}

struct SafeValue;

impl Redact for SafeValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("SafeValue", |_| {});
    }
}
