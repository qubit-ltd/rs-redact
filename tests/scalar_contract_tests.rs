// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public scalar admission and failure provenance contracts.

use std::cell::Cell;
use std::ffi::OsStr;
use std::fmt;
use std::iter::once;

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionSummary;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;

/// Builds an independent redactor with exact input and output allowances.
fn bounded(input: usize, output: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(input).max_output_bytes(output);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    Redactor::new(policy)
}

/// Checks the sole non-output failure when a safe replacement fits.
fn assert_failure(summary: &RedactionSummary, reason: RedactionReason, inspected: usize) {
    assert_eq!(summary.completion(), RedactionCompletion::Truncated);
    assert_eq!(summary.usage().inspected_input_bytes(), inspected);
    for candidate in [
        RedactionReason::InputLimitReached,
        RedactionReason::FormattingFailed,
        RedactionReason::OutputLimitReached,
    ] {
        assert_eq!(
            summary.reasons().contains(candidate),
            candidate == reason,
            "{candidate:?}"
        );
    }
}

/// Counts value access independently of its diagnostic representation.
struct Counted<'a>(&'a Cell<usize>);

impl fmt::Display for Counted<'_> {
    /// Emits a secret only if the caller actually invokes this formatter.
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        output.write_str("raw-secret")
    }
}

/// Refuses formatting without encountering a writer limit.
struct Refuses;

impl fmt::Display for Refuses {
    /// Returns a formatter-originated failure, not an admission failure.
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Err(fmt::Error)
    }
}

#[test]
fn test_key_admission_precedes_secret_formatting_in_all_publication_modes() {
    let redactor = bounded(4, 128);
    let calls = Cell::new(0);
    let value = Counted(&calls);
    let direct = redactor.redact_field("password", &value);
    let composed = redactor.text_composer().field("password", &value).finish();
    let mut batch = redactor.batch();
    let handle = batch.redact_field("password", &value);
    let diagnostics = batch.finish_for_diagnostics("<incomplete>");
    for summary in [direct.summary(), composed.summary(), diagnostics.summary()] {
        assert_failure(summary, RedactionReason::InputLimitReached, 0);
        assert_eq!(summary.usage().presented_input_bytes(), 8);
    }
    assert_eq!(direct.text().as_str(), "<truncated>");
    assert_eq!(direct.text(), composed.text());
    assert_eq!(diagnostics.text(handle).as_str(), "<incomplete>");
    assert_eq!(calls.get(), 0);
}

#[test]
fn test_input_writer_rejection_is_not_formatter_or_output_failure() {
    let output = bounded(4, 128).redact_field("user", "a");
    assert_failure(output.summary(), RedactionReason::InputLimitReached, 4);
    assert_eq!(output.summary().usage().presented_input_bytes(), 5);
    assert_eq!(output.text().as_str(), "<truncated>");
}

#[test]
fn test_formatter_failure_keeps_its_own_reason() {
    let output = bounded(64, 128).redact_field("user", &Refuses);
    assert_failure(output.summary(), RedactionReason::FormattingFailed, 4);
    assert_eq!(output.text().as_str(), "<truncated>");
}

#[test]
fn test_failed_replacement_records_actual_output_rejection() {
    let output = bounded(4, 1).redact_field("user", "a");
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(!output.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert!(output.text().as_str().is_empty());
}

#[test]
fn test_exact_key_allowance_does_not_inspect_an_opaque_secret() {
    let calls = Cell::new(0);
    let output = bounded(8, 128).redact_field("password", &Counted(&calls));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 8);
    assert_eq!(output.text().as_str(), "<redacted>");
    assert_eq!(calls.get(), 0);
}

#[test]
fn test_input_rejection_does_not_close_a_batch_with_remaining_allowance() {
    let mut batch = bounded(4, 128).batch();
    let first = batch.redact_field("password", "raw-secret");
    let second = batch.redact_field("id", "ok");
    let output = batch.finish_for_diagnostics("<incomplete>");
    assert_eq!(output.text(first).as_str(), "<incomplete>");
    assert_eq!(output.text(second).as_str(), "ok");
    assert_failure(output.summary(), RedactionReason::InputLimitReached, 4);
}

#[test]
fn test_batch_keys_share_the_input_allowance() {
    let mut batch = bounded(8, 128).batch();
    let first = batch.redact_field("password", "first-secret");
    let second = batch.redact_field("password", "second-secret");
    let output = batch.finish_for_diagnostics("<incomplete>");
    assert_eq!(output.text(first).as_str(), "<redacted>");
    assert_eq!(output.text(second).as_str(), "<incomplete>");
    assert_failure(output.summary(), RedactionReason::InputLimitReached, 8);
}

#[test]
fn test_utf8_input_and_escaped_output_have_distinct_byte_units() {
    let output = bounded(4, 128).redact_field("x", "é\n");
    assert_eq!(output.text().as_str(), "é\\n");
    assert_eq!(output.summary().usage().inspected_input_bytes(), 4);
    assert_eq!(output.summary().usage().output_bytes(), 4);
    let rejected = bounded(3, 128).redact_field("x", "é\n");
    assert_failure(rejected.summary(), RedactionReason::InputLimitReached, 1);
}

/// Attempts additional writes even after the capture returns an error.
struct IgnoresRejection;

impl fmt::Display for IgnoresRejection {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("ab")?;
        let _ = output.write_str("too-long");
        let _ = output.write_str("c");
        Ok(())
    }
}

#[test]
fn test_capture_failure_latches_and_keeps_only_admitted_usage() {
    let output = bounded(4, 128).redact_field("x", &IgnoresRejection);
    assert_failure(output.summary(), RedactionReason::InputLimitReached, 3);
    assert_eq!(output.summary().usage().presented_input_bytes(), 12);
    assert_eq!(output.text().as_str(), "<truncated>");
}

#[test]
fn test_output_rejection_closes_subsequent_access_and_preserves_safe_prefix() {
    let calls = Cell::new(0);
    let output = bounded(128, 20)
        .text_composer()
        .literal("safe:")
        .field("x", "a long visible value")
        .field("x", &Counted(&calls))
        .finish();
    assert_eq!(output.text().as_str(), "safe:a lo<truncated>");
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(!output.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert_eq!(calls.get(), 0);
}

#[test]
fn test_structural_rejection_precedes_key_input_and_value_access() {
    for (depth, key, reason) in [
        (0, 128, RedactionReason::DepthLimitReached),
        (32, 0, RedactionReason::TraversalLimitReached),
    ] {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_depth(depth).max_key_bytes(key).max_input_bytes(0);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let calls = Cell::new(0);
        let output = Redactor::new(policy).redact_field("password", &Counted(&calls));
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(reason));
        assert!(!output.summary().reasons().contains(RedactionReason::InputLimitReached));
        assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
        assert_eq!(output.summary().usage().presented_input_bytes(), 0);
        assert_eq!(calls.get(), 0);
    }
}

/// Produces output whose UTF-8 boundary leaves spare bytes after truncation.
struct WideDomain;

impl Redact for WideDomain {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("界界界界界界界界");
    }
}

#[test]
fn test_domain_output_rejection_closes_later_scalar_access() {
    let redactor = bounded(128, 21);
    let calls = Cell::new(0);
    let output = redactor
        .text_composer()
        .value(&WideDomain)
        .field("x", &Counted(&calls))
        .finish();
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(calls.get(), 0, "composer must preserve domain output closure");
    let mut batch = redactor.batch();
    let _first = batch.redact_value(&WideDomain);
    let _second = batch.redact_field("x", &Counted(&calls));
    let _output = batch.finish_for_diagnostics("<incomplete>");
    assert_eq!(calls.get(), 0, "batch must preserve domain output closure");
}

#[test]
fn test_process_batch_stops_environment_access_after_argv_output_rejection() {
    let calls = Cell::new(0);
    let variables = once((OsStr::new("MODE"), OsStr::new("debug"))).inspect(|_| {
        calls.set(calls.get() + 1);
    });
    let mut batch = bounded(128, 20).batch();
    let handle = batch.redact_process(
        OsStr::new("a-program-name-longer-than-the-output-budget"),
        [],
        variables,
    );
    let output = batch.finish_for_diagnostics("<incomplete>");
    assert_eq!(
        calls.get(),
        0,
        "closed argv output must prevent reading environment input"
    );
    assert_eq!(output.text(handle).as_str(), "<incomplete>");
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
}
