// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(all(feature = "derive", feature = "serde"))]

use std::cell::Cell;
use std::fmt;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::domain::internal::RedactSerializeScope;
use qubit_redact::domain::internal::RedactedSerializeRef;

struct Rr2SerdeCounted<'a>(&'a Cell<usize>);

impl fmt::Display for Rr2SerdeCounted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in 0..5 {
            self.0.set(self.0.get() + 1);
            f.write_str("a")?;
        }
        Ok(())
    }
}

#[derive(Redact)]
#[redact(serde)]
struct Rr2SerdeRecord<'a> {
    #[redact(display, level = "low")]
    a: Rr2SerdeCounted<'a>,
    #[redact(display, level = "low")]
    b: Rr2SerdeCounted<'a>,
}

#[test]
fn test_rr2_serde_failed_prefix_is_charged() {
    for source in [false, true] {
        let a = Cell::new(0);
        let b = Cell::new(0);
        let value = Rr2SerdeRecord {
            a: Rr2SerdeCounted(&a),
            b: Rr2SerdeCounted(&b),
        };
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_input_bytes(4);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let encoded = if source {
            let _scope = RedactSerializeScope::new(&policy);
            serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).expect("safe source replacement")
        } else {
            serde_json::to_value(Redactor::new(policy).redact_view(&value)).expect("safe view replacement")
        };
        assert_eq!(a.get(), 5);
        assert!(
            b.get() <= 1,
            "second formatter cannot reuse four accepted bytes (source={source}, attempts={})",
            b.get()
        );
        assert_eq!(encoded["a"], "<redacted>");
        assert_eq!(encoded["b"], "<redacted>");
    }
}

struct Rr2SerdeFormatterError<'a>(&'a Cell<usize>);

impl fmt::Display for Rr2SerdeFormatterError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in 0..4 {
            self.0.set(self.0.get() + 1);
            f.write_str("a")?;
        }
        Err(fmt::Error)
    }
}

#[derive(Redact)]
#[redact(serde)]
struct Rr2SerdeErrorRecord<'a> {
    #[redact(display, level = "low")]
    a: Rr2SerdeFormatterError<'a>,
    #[redact(display, level = "low")]
    b: Rr2SerdeCounted<'a>,
}

#[test]
fn test_rr2_serde_formatter_error_still_charges_prefix() {
    let a = Cell::new(0);
    let b = Cell::new(0);
    let value = Rr2SerdeErrorRecord {
        a: Rr2SerdeFormatterError(&a),
        b: Rr2SerdeCounted(&b),
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(4);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let _scope = RedactSerializeScope::new(&policy);

    let encoded = serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).expect("safe source replacement");

    assert_eq!(a.get(), 4);
    assert_eq!(b.get(), 1, "failed formatter prefix remains charged");
    assert_eq!(encoded["a"], "<redacted>");
    assert_eq!(encoded["b"], "<redacted>");
}

struct Rr2SerdeIgnoredUtf8Rejection;

impl fmt::Display for Rr2SerdeIgnoredUtf8Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f.write_str("éé");
        Ok(())
    }
}

#[derive(Redact)]
#[redact(serde)]
struct Rr2SerdeIgnoredErrorRecord {
    #[redact(display, level = "low")]
    value: Rr2SerdeIgnoredUtf8Rejection,
}

#[test]
fn test_rr2_serde_ignored_write_error_keeps_utf8_fragment_atomic() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(3);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let value = Rr2SerdeIgnoredErrorRecord {
        value: Rr2SerdeIgnoredUtf8Rejection,
    };

    let encoded = serde_json::to_value(RedactedSerializeRef::new(&value, &policy))
        .expect("safe replacement after ignored write error");

    assert_eq!(encoded["value"], "<redacted>");
}

struct Rr2SerdeExact<'a>(&'a Cell<usize>, &'static str);

impl fmt::Display for Rr2SerdeExact<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        f.write_str(self.1)
    }
}

#[derive(Redact)]
#[redact(serde)]
struct Rr2SerdeExactRecord<'a> {
    #[redact(display, level = "low")]
    a: Rr2SerdeExact<'a>,
    #[redact(display, level = "low")]
    b: Rr2SerdeExact<'a>,
}

#[test]
fn test_rr2_serde_exact_input_budget_is_charged_once() {
    let a = Cell::new(0);
    let b = Cell::new(0);
    let value = Rr2SerdeExactRecord {
        a: Rr2SerdeExact(&a, "aaaa"),
        b: Rr2SerdeExact(&b, "b"),
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(5);
        })
        .expect("limits")
        .build()
        .expect("policy");

    let encoded =
        serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).expect("exactly admitted source values");

    assert_eq!(a.get(), 1);
    assert_eq!(b.get(), 1);
    assert_eq!(encoded["a"], "****");
    assert_eq!(encoded["b"], "****");
}

#[test]
fn test_rr2_serde_zero_input_budget_fails_closed() {
    let a = Cell::new(0);
    let b = Cell::new(0);
    let value = Rr2SerdeExactRecord {
        a: Rr2SerdeExact(&a, "a"),
        b: Rr2SerdeExact(&b, "b"),
    };
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(0);
        })
        .expect("limits")
        .build()
        .expect("policy");

    let encoded = serde_json::to_value(RedactedSerializeRef::new(&value, &policy))
        .expect("zero input budget should produce safe replacements");

    assert_eq!(a.get(), 1);
    assert_eq!(b.get(), 1);
    assert_eq!(encoded["a"], "<redacted>");
    assert_eq!(encoded["b"], "<redacted>");
}

struct Rr2SerdePanicDisplay;

impl fmt::Display for Rr2SerdePanicDisplay {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("high sensitivity formatter must remain lazy");
    }
}

#[derive(Redact)]
#[redact(serde)]
struct Rr2SerdeHighRecord {
    #[redact(display, level = "secret")]
    value: Rr2SerdePanicDisplay,
}

#[test]
fn test_rr2_serde_high_sensitivity_does_not_format() {
    let policy = RedactionPolicy::builder().build().expect("policy");
    let value = Rr2SerdeHighRecord {
        value: Rr2SerdePanicDisplay,
    };

    let encoded =
        serde_json::to_value(RedactedSerializeRef::new(&value, &policy)).expect("high sensitivity replacement");

    assert_eq!(encoded["value"], "<redacted>");
}
