// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::cell::Cell;
use std::fmt;

use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

struct Counted<'a>(&'a Cell<usize>);

impl fmt::Display for Counted<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        formatter.write_str("secret text")
    }
}

struct Refuses;

impl fmt::Display for Refuses {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Err(fmt::Error)
    }
}

fn limited_policy(
    max_nodes: usize,
    max_key_bytes: usize,
    max_input_bytes: usize,
    max_output_bytes: usize,
) -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_nodes(max_nodes)
                .max_key_bytes(max_key_bytes)
                .max_input_bytes(max_input_bytes)
                .max_output_bytes(max_output_bytes);
        })
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn test_minimum_secret_masks_arbitrary_key_without_formatting() {
    let calls = Cell::new(0);
    let value = Counted(&calls);
    let output = Redactor::standard().redact_field_at_least(Sensitivity::Secret, "detail", &value);
    assert_eq!(output.text().as_str(), "<redacted>");
    assert_eq!(calls.get(), 0);
}

#[test]
fn test_composer_minimum_matches_direct_api() {
    let direct = Redactor::standard().redact_field_at_least(Sensitivity::Secret, "detail", "secret text");
    let composed = Redactor::standard()
        .text_composer()
        .field_at_least(Sensitivity::Secret, "detail", "secret text")
        .finish();
    assert_eq!(composed.text(), direct.text());
    assert_eq!(composed.summary(), direct.summary());
}

#[test]
fn test_policy_secret_classification_is_stronger_than_low_minimum() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise("detail", Sensitivity::Secret);
        })
        .unwrap()
        .build()
        .unwrap();
    let output = Redactor::new(policy).redact_field_at_least(Sensitivity::Low, "detail", "secret text");
    assert_eq!(output.text().as_str(), "<redacted>");
}

#[test]
fn test_minimum_is_not_lowered_by_allow_or_disabled_floor() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.disable_floor().allow_exact("detail");
        })
        .unwrap()
        .build()
        .unwrap();
    let output = Redactor::new(policy).redact_field_at_least(Sensitivity::Secret, "detail", "secret text");
    assert_eq!(output.text().as_str(), "<redacted>");
}

#[test]
fn test_disabled_policy_restores_value_with_minimum() {
    let output =
        Redactor::new(RedactionPolicy::disabled()).redact_field_at_least(Sensitivity::Secret, "detail", "secret text");
    assert_eq!(output.text().as_str(), "secret text");
}

#[test]
fn test_minimum_respects_utf8_key_and_node_admission_before_display() {
    let calls = Cell::new(0);
    let value = Counted(&calls);
    let exact = Redactor::new(limited_policy(1, 3, 64, 64)).redact_field_at_least(Sensitivity::Low, "名", &value);
    assert!(!exact.text().as_str().is_empty());
    assert_eq!(calls.get(), 1);

    let calls = Cell::new(0);
    let rejected =
        Redactor::new(limited_policy(1, 2, 64, 64)).redact_field_at_least(Sensitivity::Low, "名", &Counted(&calls));
    assert!(
        rejected
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert_eq!(calls.get(), 0);

    let calls = Cell::new(0);
    let rejected =
        Redactor::new(limited_policy(0, 8, 64, 64)).redact_field_at_least(Sensitivity::Low, "detail", &Counted(&calls));
    assert!(
        rejected
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert_eq!(calls.get(), 0);
}

#[test]
fn test_minimum_input_rejection_precedes_display() {
    let calls = Cell::new(0);
    let output =
        Redactor::new(limited_policy(1, 64, 5, 64)).redact_field_at_least(Sensitivity::Low, "detail", &Counted(&calls));
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert_eq!(calls.get(), 0);
}

#[test]
fn test_minimum_preserves_formatter_and_output_failures() {
    let formatter = Redactor::standard().redact_field_at_least(Sensitivity::Low, "detail", &Refuses);
    assert!(
        formatter
            .summary()
            .reasons()
            .contains(RedactionReason::FormattingFailed)
    );

    let output =
        Redactor::new(limited_policy(1, 64, 64, 1)).redact_field_at_least(Sensitivity::Low, "detail", "visible text");
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
}
