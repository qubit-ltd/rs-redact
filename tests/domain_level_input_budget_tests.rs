// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "derive")]

use std::cell::Cell;
use std::fmt;

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

struct Rr2Counted<'a>(&'a Cell<usize>);

impl fmt::Debug for Rr2Counted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Rr2Counted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in 0..5 {
            self.0.set(self.0.get() + 1);
            f.write_str("a")?;
        }
        Ok(())
    }
}

#[derive(Redact)]
struct Rr2InputRecord<'a> {
    #[redact(display, level = "low")]
    a: Rr2Counted<'a>,
    #[redact(display, level = "low")]
    b: Rr2Counted<'a>,
}

#[test]
fn test_rr2_explicit_display_shares_input_allowance() {
    let a = Cell::new(0);
    let b = Cell::new(0);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(4);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact_text(&Rr2InputRecord {
        a: Rr2Counted(&a),
        b: Rr2Counted(&b),
    });
    assert_eq!(a.get(), 5);
    assert_eq!(b.get(), 0);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 4);
    assert_eq!(output.summary().usage().presented_input_bytes(), 5);
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(!output.text().as_str().contains("aaaa"));
}

#[test]
fn test_rr2_explicit_low_medium_inspection_does_not_format_values() {
    let a = Cell::new(0);
    let b = Cell::new(0);
    let inspected = Redactor::standard()
        .inspect(&Rr2InputRecord {
            a: Rr2Counted(&a),
            b: Rr2Counted(&b),
        })
        .expect("inspection is conclusive without formatting scalar text");
    assert_eq!(a.get(), 0);
    assert_eq!(b.get(), 0);
    assert!(inspected.contains_sensitive());
}

#[test]
fn test_rr2_explicit_display_zero_input_allowance_rejects_first_chunk() {
    let a = Cell::new(0);
    let b = Cell::new(0);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(0);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact_text(&Rr2InputRecord {
        a: Rr2Counted(&a),
        b: Rr2Counted(&b),
    });
    assert_eq!(a.get(), 1);
    assert_eq!(b.get(), 0);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 0);
    assert_eq!(output.summary().usage().presented_input_bytes(), 1);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
}

#[test]
fn test_rr2_successful_mask_does_not_charge_generated_text_again() {
    let calls = Cell::new(0);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(5);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact_text(&Rr2ScriptRecord {
        value: Rr2Script {
            calls: &calls,
            mode: Rr2FormatMode::IgnoreInputError,
        },
    });
    assert_eq!(calls.get(), 1);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 2);
    assert_eq!(output.summary().usage().presented_input_bytes(), 2);
    assert!(!output.summary().reasons().contains(RedactionReason::InputLimitReached));
}

#[test]
fn test_rr2_disabled_explicit_display_still_uses_shared_input_allowance() {
    let a = Cell::new(0);
    let b = Cell::new(0);
    let mut policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(4);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let _ = policy.set_disabled(true);
    let output = Redactor::new(policy).redact_text(&Rr2InputRecord {
        a: Rr2Counted(&a),
        b: Rr2Counted(&b),
    });
    assert_eq!(a.get(), 5);
    assert_eq!(b.get(), 0);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 4);
    assert_eq!(output.summary().usage().presented_input_bytes(), 5);
    assert!(!output.text().as_str().contains("aaaa"));
}

#[derive(Clone, Copy)]
enum Rr2FormatMode {
    Utf8Chunk,
    FormatterError,
    IgnoreInputError,
}

struct Rr2Script<'a> {
    calls: &'a Cell<usize>,
    mode: Rr2FormatMode,
}

impl fmt::Display for Rr2Script<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.calls.set(self.calls.get() + 1);
        match self.mode {
            Rr2FormatMode::Utf8Chunk => f.write_str("é"),
            Rr2FormatMode::FormatterError => {
                f.write_str("ab")?;
                Err(fmt::Error)
            }
            Rr2FormatMode::IgnoreInputError => {
                let _ = f.write_str("ab");
                Ok(())
            }
        }
    }
}

#[derive(Redact)]
struct Rr2ScriptRecord<'a> {
    #[redact(display, level = "low")]
    value: Rr2Script<'a>,
}

#[test]
fn test_rr2_display_capture_rejects_utf8_chunks_atomically() {
    let calls = Cell::new(0);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(1);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact_text(&Rr2ScriptRecord {
        value: Rr2Script {
            calls: &calls,
            mode: Rr2FormatMode::Utf8Chunk,
        },
    });
    assert_eq!(calls.get(), 1);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 0);
    assert_eq!(output.summary().usage().presented_input_bytes(), "é".len());
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(!output.text().as_str().contains('é'));
}

#[test]
fn test_rr2_display_formatter_errors_keep_accepted_prefix_usage() {
    let calls = Cell::new(0);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(4);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact_text(&Rr2ScriptRecord {
        value: Rr2Script {
            calls: &calls,
            mode: Rr2FormatMode::FormatterError,
        },
    });
    assert_eq!(calls.get(), 1);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 2);
    assert_eq!(output.summary().usage().presented_input_bytes(), 2);
    assert!(output.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert!(!output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(!output.text().as_str().contains("ab"));
}

#[test]
fn test_rr2_display_ignored_input_error_stays_latched() {
    let calls = Cell::new(0);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(1);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact_text(&Rr2ScriptRecord {
        value: Rr2Script {
            calls: &calls,
            mode: Rr2FormatMode::IgnoreInputError,
        },
    });
    assert_eq!(calls.get(), 1);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 0);
    assert_eq!(output.summary().usage().presented_input_bytes(), 2);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(!output.summary().reasons().contains(RedactionReason::FormattingFailed));
    assert!(!output.text().as_str().contains("ab"));
}

struct Rr2PanicDisplay;
impl fmt::Display for Rr2PanicDisplay {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("opaque or inspected values must not be formatted");
    }
}

#[derive(Redact)]
struct Rr2OpaqueRecord {
    #[redact(display, level = "high")]
    high: Rr2PanicDisplay,
    #[redact(display, level = "secret")]
    secret: Rr2PanicDisplay,
}

#[test]
fn test_rr2_high_secret_and_inspection_do_not_format_display_values() {
    let value = Rr2OpaqueRecord {
        high: Rr2PanicDisplay,
        secret: Rr2PanicDisplay,
    };
    let redactor = Redactor::standard();
    let output = redactor.redact_text(&value);
    assert!(!output.text().as_str().contains("opaque or inspected"));
    let inspection = redactor.inspect(&value).expect("inspection skips scalar formatting");
    assert!(inspection.contains_sensitive());
}

#[test]
fn test_rr2_input_fallback_adds_output_limit_only_when_marker_cannot_fit() {
    struct SmallOutputRecord<'a>(&'a Cell<usize>);
    impl Redact for SmallOutputRecord<'_> {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.tuple("T", |fields| {
                fields.sensitive_at_least(Sensitivity::Low, "value", || Rr2Counted(self.0));
            });
        }
    }

    let calls = Cell::new(0);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(4).max_output_bytes(3);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let output = Redactor::new(policy).redact_text(&SmallOutputRecord(&calls));
    assert_eq!(calls.get(), 5);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
}
