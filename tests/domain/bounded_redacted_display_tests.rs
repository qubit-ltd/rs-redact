// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for bounded display of already-redacted views.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use qubit_redact::LogOutputLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::Redact;
use qubit_redact::RedactedMap;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSession;
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
    fn redaction_input_bytes(&self) -> usize {
        self.value.len()
    }

    /// Writes the configured text using the standard debug string format.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        fmt::Debug::fmt(&self.value, formatter)
    }
}

impl Redact for DiagnosticText<'_> {
    fn redaction_input_bytes(&self) -> usize {
        self.value.len()
    }

    /// Writes the configured diagnostic text.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
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
    LogOutputLimit::new(max_bytes).expect("the test budget can contain the truncation marker")
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

/// Verifies the bounded adapter also constrains debug formatting.
#[test]
fn test_bounded_redacted_display_debug_is_bounded() {
    let value = DiagnosticText {
        value: "content exceeds the minimum budget",
    };

    let actual = format!(
        "{:?}",
        value
            .redacted()
            .with_output_limit(limit(LogOutputLimit::MINIMUM)),
    );

    assert_eq!(actual, "<truncated>");
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

/// Verifies eager completion also floors an already-buffered prefix to a UTF-8
/// boundary before appending its marker.
#[test]
fn test_eager_completion_floors_buffered_unicode_boundary() {
    struct SplitUnicode;

    impl Redact for SplitUnicode {
        fn redaction_input_bytes(&self) -> usize {
            "你好你你你你你".len()
        }

        fn fmt_redacted(
            &self,
            _session: &mut RedactionSession<'_>,
            formatter: &mut fmt::Formatter<'_>,
        ) -> fmt::Result {
            formatter.write_str("你好")?;
            formatter.write_str("你你你你你")
        }
    }

    let output = SplitUnicode
        .redacted()
        .with_output_limit(limit(15))
        .to_string();

    assert_eq!(output, "你<truncated>");
}

/// Verifies a domain-local mask ceiling does not close the shared session.
#[test]
fn test_domain_truncation_keeps_session_open_for_later_fragments() {
    struct TwoMasks<'a>(&'a AtomicUsize);

    impl Redact for TwoMasks<'_> {
        fn redaction_input_bytes(&self) -> usize {
            "secret".len().saturating_mul(2)
        }

        fn fmt_redacted(
            &self,
            session: &mut RedactionSession<'_>,
            formatter: &mut fmt::Formatter<'_>,
        ) -> fmt::Result {
            for _ in 0..2 {
                let masked = session.redact_at(qubit_redact::Sensitivity::Secret, "secret");
                if !masked.as_str().is_empty() {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
            formatter.write_str("safe")
        }
    }

    let completed = AtomicUsize::new(0);
    let policy = RedactionPolicy::builder()
        .mask(
            qubit_redact::Sensitivity::Secret,
            MaskPolicy::fixed(&"你".repeat(20)),
        )
        .expect("the Unicode mask should be valid")
        .build()
        .expect("the policy should build");
    let output = TwoMasks(&completed)
        .redacted_with(&policy)
        .with_output_limit(limit(14))
        .to_string();

    assert_eq!(completed.load(Ordering::Relaxed), 2);
    assert_eq!(output, "safe");
}

/// Value that must never render when its input cannot be admitted.
struct AdmissionObserver<'a> {
    calls: &'a AtomicUsize,
    text: String,
}

impl Redact for AdmissionObserver<'_> {
    fn redaction_input_bytes(&self) -> usize {
        self.text.len()
    }

    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        self.calls.fetch_add(1, Ordering::Relaxed);
        formatter.write_str(&self.text)
    }
}

/// Verifies an existing bounded-mask context does not bypass input admission.
#[test]
fn test_bounded_debug_admits_before_fmt_redacted() {
    let calls = AtomicUsize::new(0);
    let value = AdmissionObserver {
        calls: &calls,
        text: "heap input".to_owned(),
    };
    let budget =
        qubit_redact::InputOutputLimit::new(1, qubit_redact::InputOutputLimit::MIN_OUTPUT_BYTES)
            .expect("the zero-input budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the policy should build");
    let output_limit = limit(qubit_redact::InputOutputLimit::MIN_OUTPUT_BYTES);

    let _ = format!(
        "{:?}",
        value.redacted_with(&policy).with_output_limit(output_limit)
    );

    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

/// Heap-backed custom value relying on the default fail-closed contract.
struct DefaultInputContract<'a> {
    calls: &'a AtomicUsize,
    text: String,
}

impl Redact for DefaultInputContract<'_> {
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        self.calls.fetch_add(1, Ordering::Relaxed);
        formatter.write_str(&self.text)
    }
}

/// Verifies the default input contract cannot charge only pointer metadata for
/// a heap-backed value.
#[test]
fn test_default_redact_input_contract_is_fail_closed() {
    let calls = AtomicUsize::new(0);
    let value = DefaultInputContract {
        calls: &calls,
        text: "x".repeat(1_000),
    };
    let budget = qubit_redact::InputOutputLimit::new(
        std::mem::size_of_val(&value),
        qubit_redact::InputOutputLimit::MIN_OUTPUT_BYTES,
    )
    .expect("the structural-sized budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the policy should build");

    let _ = format!("{:?}", value.redacted_with(&policy));

    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

/// Verifies an unlimited numeric budget cannot admit the sentinel used for an
/// unmeasurable custom input.
#[test]
fn test_default_redact_input_contract_is_fail_closed_at_usize_max() {
    let calls = AtomicUsize::new(0);
    let value = DefaultInputContract {
        calls: &calls,
        text: "heap input".to_owned(),
    };
    let budget = qubit_redact::InputOutputLimit::new(
        usize::MAX,
        qubit_redact::InputOutputLimit::MIN_OUTPUT_BYTES,
    )
    .expect("the maximum input budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the policy should build");

    let output = format!("{:?}", value.redacted_with(&policy));

    assert_eq!(output, "<truncated>");
    assert_eq!(calls.load(Ordering::Relaxed), 0);
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

/// Value that writes one complete escape before a later write overflows.
struct SplitEscapeDiagnostic {
    prefix: &'static str,
}

impl Redact for SplitEscapeDiagnostic {
    fn redaction_input_bytes(&self) -> usize {
        0
    }

    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str(self.prefix)?;
        formatter.write_str("remaining-long")
    }
}

/// Verifies final truncation rechecks the complete prefix before a `\\xNN`
/// escape retained by an earlier write.
#[test]
fn test_bounded_redacted_display_does_not_split_buffered_hex_escape() {
    let value = SplitEscapeDiagnostic { prefix: r"a\x1b" };

    let actual = value.redacted().with_output_limit(limit(15)).to_string();

    assert_eq!(actual, "a<truncated>");
}

/// Verifies final truncation rechecks the complete prefix before a `\\u{...}`
/// escape retained by an earlier write.
#[test]
fn test_bounded_redacted_display_does_not_split_buffered_unicode_escape() {
    let value = SplitEscapeDiagnostic { prefix: r"a\u{1f}" };

    let actual = value.redacted().with_output_limit(limit(15)).to_string();

    assert_eq!(actual, "a<truncated>");
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
    fn redaction_input_bytes(&self) -> usize {
        0
    }

    /// Writes many safe pieces and propagates the first destination error.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
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
