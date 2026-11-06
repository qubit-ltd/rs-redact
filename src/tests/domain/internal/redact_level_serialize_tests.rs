// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Level-aware display admission and internal report contracts.

use std::cell::Cell;
use std::fmt;

use serde_json::value::Serializer as JsonSerializer;

use crate::RedactionPolicy;
use crate::RedactionReason;
use crate::RedactionReasons;
use crate::Sensitivity;
use crate::domain::internal::DisplayValue;
use crate::domain::internal::RedactLevelSerialize;
use crate::domain::internal::RedactSerializeScope;
use crate::domain::internal::register_report;

struct Refuses;

impl fmt::Display for Refuses {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Err(fmt::Error)
    }
}

struct Counted<'a>(&'a Cell<usize>);

impl fmt::Display for Counted<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        formatter.write_str("counted")
    }
}

#[test]
fn test_display_error_and_input_rejection_are_reported() {
    let policy = RedactionPolicy::standard();
    let _scope = RedactSerializeScope::new(&policy);
    let report = register_report();
    let value = DisplayValue::new(&Refuses)
        .serialize_redacted_level(JsonSerializer, &policy, Sensitivity::Low)
        .expect("formatter failure uses safe replacement");
    assert_eq!(value, "<redacted>");
    assert!(
        report.reasons().contains(RedactionReason::FormattingFailed),
        "formatter failure must be recorded in the active report",
    );

    drop(report);
    drop(_scope);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(0);
        })
        .unwrap()
        .build()
        .unwrap();
    let _scope = RedactSerializeScope::new(&policy);
    let report = register_report();
    let value = DisplayValue::new("too-long")
        .serialize_redacted_level(JsonSerializer, &policy, Sensitivity::Low)
        .expect("input rejection uses safe replacement");
    assert_eq!(value, "<redacted>");
    assert!(
        report.reasons().contains(RedactionReason::InputLimitReached),
        "input rejection must be recorded in the active report",
    );
}

#[test]
fn test_high_sensitivity_does_not_call_display_and_exact_input_budget_is_complete() {
    let calls = Cell::new(0);
    let policy = RedactionPolicy::standard();
    let _scope = RedactSerializeScope::new(&policy);
    let report = register_report();
    let value = DisplayValue::new(&Counted(&calls))
        .serialize_redacted_level(JsonSerializer, &policy, Sensitivity::Secret)
        .expect("secret mask serializes");
    assert_eq!(value, "<redacted>");
    assert_eq!(calls.get(), 0);
    let high = DisplayValue::new(&Counted(&calls))
        .serialize_redacted_level(JsonSerializer, &policy, Sensitivity::High)
        .expect("high sensitivity mask serializes");
    assert_eq!(high, policy.masking().mask_opaque(Sensitivity::High));
    assert_eq!(calls.get(), 0);
    assert_eq!(report.reasons(), RedactionReasons::empty());

    drop(report);
    drop(_scope);
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(6);
        })
        .unwrap()
        .build()
        .unwrap();
    let _scope = RedactSerializeScope::new(&policy);
    let report = register_report();
    let _ = DisplayValue::new("sixsix")
        .serialize_redacted_level(JsonSerializer, &policy, Sensitivity::Low)
        .expect("exact input boundary serializes");
    assert_eq!(report.reasons(), RedactionReasons::empty());
}
