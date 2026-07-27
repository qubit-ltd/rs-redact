// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for bounded display of already-redacted views.

use std::{
    collections::BTreeMap,
    fmt,
    sync::atomic::{
        AtomicUsize,
        Ordering,
    },
};

use qubit_redact::{
    LogOutputLimit,
    Redact,
    RedactedMap,
    RedactionPolicy,
};

/// Value whose redacted representation writes caller-selected safe text.
struct DiagnosticText<'a> {
    /// Text written through the redacted formatting contract.
    value: &'a str,
}

/// Value whose redacted representation delegates escaping to Rust debug.
struct DebugDiagnosticText<'a> {
    /// Text to render through the standard debug formatter.
    value: &'a str,
}

impl Redact for DebugDiagnosticText<'_> {
    /// Writes the configured text using the standard debug string format.
    fn fmt_redacted(
        &self,
        _policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        fmt::Debug::fmt(&self.value, formatter)
    }
}

impl Redact for DiagnosticText<'_> {
    /// Writes the configured diagnostic text.
    fn fmt_redacted(
        &self,
        _policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str(self.value)
    }
}

/// Builds a validated output limit.
///
/// # Parameters
///
/// * `max_bytes` - Maximum rendered bytes including a truncation marker.
///
/// # Returns
///
/// A validated log output limit.
fn limit(max_bytes: usize) -> LogOutputLimit {
    LogOutputLimit::new(max_bytes)
        .expect("the test budget can contain the truncation marker")
}

/// Verifies complete bounded output matches ordinary redacted display.
#[test]
fn test_bounded_redacted_display_preserves_complete_output() {
    let value = DiagnosticText {
        value: "visible text",
    };
    let expected = value.redacted().to_string();

    let actual = value
        .redacted()
        .with_output_limit(limit(expected.len()))
        .to_string();

    assert_eq!(actual, expected);
}

/// Verifies the minimum budget emits only the complete truncation marker.
#[test]
fn test_bounded_redacted_display_uses_marker_only_at_minimum() {
    let value = DiagnosticText {
        value: "content exceeds the minimum budget",
    };

    let actual = value
        .redacted()
        .with_output_limit(limit(LogOutputLimit::MINIMUM))
        .to_string();

    assert_eq!(actual, "<truncated>");
}

/// Verifies ASCII output retains the longest complete prefix before the marker.
#[test]
fn test_bounded_redacted_display_truncates_ascii_at_budget() {
    let value = DiagnosticText {
        value: "abcdefghijklmno",
    };

    let actual = value.redacted().with_output_limit(limit(14)).to_string();

    assert_eq!(actual, "abc<truncated>");
    assert_eq!(actual.len(), 14);
}

/// Verifies truncation never splits a multibyte UTF-8 character.
#[test]
fn test_bounded_redacted_display_keeps_unicode_boundary() {
    let value = DiagnosticText {
        value: "你好吗世界",
    };

    let actual = value.redacted().with_output_limit(limit(14)).to_string();

    assert_eq!(actual, "你<truncated>");
    assert_eq!(actual.len(), 14);
}

/// Verifies truncation treats one escaped control as an indivisible piece.
#[test]
fn test_bounded_redacted_display_keeps_escape_sequence_boundary() {
    let value = DiagnosticText {
        value: "ab\nremaining-long",
    };

    let actual = value.redacted().with_output_limit(limit(14)).to_string();

    assert_eq!(actual, "ab<truncated>");
    assert!(!actual.ends_with("\\<truncated>"));
}

/// Verifies truncation preserves one escape emitted by a nested debug
/// formatter.
#[test]
fn test_bounded_redacted_display_does_not_split_debug_escape_sequence() {
    let value = DebugDiagnosticText {
        value: "ab\nremaining-long",
    };

    let actual = value.redacted().with_output_limit(limit(15)).to_string();

    assert_eq!(actual, "\"ab<truncated>");
    assert!(!actual.ends_with("\\<truncated>"));
}

/// Verifies the same output contract applies to redacted map views.
#[test]
fn test_bounded_redacted_map_display_respects_budget() {
    let map = BTreeMap::from([("label", "a visible but long map value")]);
    let output = RedactedMap::new(&map, RedactionPolicy::default())
        .with_output_limit(limit(24))
        .to_string();

    assert!(output.len() <= 24, "{output}");
    assert!(output.ends_with("<truncated>"), "{output}");
}

/// Counts formatter writes so the test can prove truncation stops traversal.
struct RepeatedDiagnostic {
    /// Number of write attempts made by the formatter.
    writes: AtomicUsize,
}

impl RepeatedDiagnostic {
    /// Creates a formatter that writes one small piece repeatedly.
    const fn new() -> Self {
        Self {
            writes: AtomicUsize::new(0),
        }
    }
}

impl Redact for RepeatedDiagnostic {
    /// Writes many safe pieces and propagates the first destination error.
    fn fmt_redacted(
        &self,
        _policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        for _ in 0..1_000_000 {
            self.writes.fetch_add(1, Ordering::Relaxed);
            formatter.write_str("x")?;
        }
        Ok(())
    }
}

/// Verifies a bounded display stops a cooperative formatter after overflow.
#[test]
fn test_bounded_redacted_display_stops_formatter_after_budget_exhaustion() {
    let value = RepeatedDiagnostic::new();

    let output = value.redacted().with_output_limit(limit(14)).to_string();

    assert_eq!(output, "xxx<truncated>");
    assert_eq!(
        value.writes.load(Ordering::Relaxed),
        limit(14).max_bytes() + 1,
    );
}
