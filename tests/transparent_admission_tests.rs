// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structural admission regressions for transparent domain values.

use std::cell::Cell;

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;

struct Transparent<'counter>(&'counter Cell<usize>);

impl Redact for Transparent<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.transparent(|fields| {
            fields.unredacted("value", || {
                self.0.set(self.0.get() + 1);
                "visible"
            });
        });
    }
}

fn policy(max_depth: usize, max_nodes: usize) -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(max_depth).max_nodes(max_nodes);
        })
        .expect("limits")
        .build()
        .expect("policy")
}

#[test]
fn test_transparent_root_depth_and_inspection_are_admitted_before_callback() {
    for base in [RedactionPolicy::standard(), RedactionPolicy::disabled()] {
        let calls = Cell::new(0);
        let redactor = Redactor::new(
            base.to_builder()
                .limits(|limits| {
                    limits.max_depth(0);
                })
                .expect("limits")
                .build()
                .expect("policy"),
        );

        let output = redactor.redact_text(&Transparent(&calls));
        assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
        assert!(output.summary().reasons().contains(RedactionReason::DepthLimitReached));
        assert_eq!(calls.get(), 0);

        let error = redactor
            .inspect(&Transparent(&calls))
            .expect_err("depth zero must reject");
        assert!(error.reasons().contains(RedactionReason::DepthLimitReached));
        assert_eq!(error.usage().output_bytes(), 0);
        assert_eq!(calls.get(), 0);
    }
}

#[test]
fn test_transparent_root_and_field_consume_nodes_and_depth() {
    let calls = Cell::new(0);
    let output = Redactor::new(policy(1, 2)).redact_text(&Transparent(&calls));
    assert_eq!(output.text().as_str(), "\"visible\"");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.summary().usage().visited_nodes(), 2);
    assert_eq!(output.summary().usage().max_depth(), 1);
    assert_eq!(calls.get(), 1);

    let calls = Cell::new(0);
    let output = Redactor::new(policy(1, 0)).redact_text(&Transparent(&calls));
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert_eq!(calls.get(), 0);

    let calls = Cell::new(0);
    let output = Redactor::new(policy(1, 1)).redact_text(&Transparent(&calls));
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert_eq!(calls.get(), 0);
}

struct NestedTransparent<'counter>(&'counter Cell<usize>);

impl Redact for NestedTransparent<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.transparent(|fields| {
            fields.nested("inner", &Transparent(self.0));
        });
    }
}

struct Utf8Transparent;

impl Redact for Utf8Transparent {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.transparent(|fields| {
            fields.unredacted("value", || "café");
        });
    }
}

#[test]
fn test_nested_transparent_depth_rejects_child_before_accessor() {
    let calls = Cell::new(0);
    let output = Redactor::new(policy(1, 8)).redact_text(&NestedTransparent(&calls));
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().reasons().contains(RedactionReason::DepthLimitReached));
    assert!(output.summary().usage().max_depth() <= 1);
    assert_eq!(calls.get(), 0);

    let calls = Cell::new(0);
    let output = Redactor::new(policy(2, 8)).redact_text(&NestedTransparent(&calls));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.summary().usage().max_depth(), 2);
    assert_eq!(calls.get(), 1);
}

#[test]
fn test_transparent_batch_carries_node_exhaustion_and_marker() {
    let redactor = Redactor::new(policy(1, 2));
    let first = Transparent(&Cell::new(0));
    let second = Transparent(&Cell::new(0));
    let mut batch = redactor.diagnostic_batch();
    let first_handle = batch.redact_value(&first);
    let second_handle = batch.redact_value(&second);
    let output = batch.finish_with_marker("<incomplete>");

    assert_eq!(output.text(first_handle).as_str(), "\"visible\"");
    assert_eq!(output.text(second_handle).as_str(), "<incomplete>");
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert_eq!(output.summary().usage().visited_nodes(), 2);
}

#[test]
fn test_transparent_output_limit_respects_utf8_boundaries() {
    let source = Utf8Transparent;
    let complete = Redactor::standard().redact_text(&source);
    let expected = complete.text().as_str().to_owned();
    let mut reached_complete = false;
    for maximum in 0..=expected.len() + 8 {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_output_bytes(maximum);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let output = Redactor::new(policy).redact_text(&source);
        assert!(output.text().as_str().len() <= maximum);
        assert_eq!(output.summary().usage().output_bytes(), output.text().as_str().len());
        if output.summary().completion() == RedactionCompletion::Complete {
            assert_eq!(output.text().as_str(), expected);
            reached_complete = true;
        } else {
            assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
            assert!(std::str::from_utf8(output.text().as_str().as_bytes()).is_ok());
        }
    }
    assert!(reached_complete, "a sufficient output limit must preserve the text");
}

#[test]
fn test_composer_transparent_siblings_leave_depth_scope() {
    let redactor = Redactor::new(policy(1, 4));
    let first = Transparent(&Cell::new(0));
    let second = Transparent(&Cell::new(0));
    let output = redactor
        .text_composer()
        .value(&first)
        .literal(" ")
        .value(&second)
        .finish();

    assert_eq!(output.text().as_str(), "\"visible\" \"visible\"");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.summary().usage().visited_nodes(), 4);
    assert_eq!(output.summary().usage().max_depth(), 1);
}

#[cfg(feature = "derive")]
mod derive_tests {
    use qubit_redact::Redact;
    use qubit_redact::RedactionPolicy;
    use qubit_redact::RedactionReason;
    use qubit_redact::Redactor;

    #[derive(Redact)]
    #[redact(transparent)]
    struct Wrapper(String);

    #[test]
    fn test_derived_transparent_obeys_root_depth() {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_depth(0);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let redactor = Redactor::new(policy);
        let output = redactor.redact_text(&Wrapper("visible".to_owned()));
        assert!(output.summary().reasons().contains(RedactionReason::DepthLimitReached));
        assert!(
            redactor
                .inspect(&Wrapper("visible".to_owned()))
                .expect_err("depth zero must reject")
                .reasons()
                .contains(RedactionReason::DepthLimitReached)
        );
    }
}

#[cfg(all(feature = "derive", feature = "serde"))]
mod serde_tests {
    use qubit_redact::Redact;
    use qubit_redact::RedactionPolicy;
    use qubit_redact::RedactionReason;
    use qubit_redact::Redactor;
    use serde::Serialize;

    #[derive(Redact, Serialize)]
    #[redact(transparent)]
    #[serde(transparent)]
    struct Wrapper(String);

    #[test]
    fn test_transparent_text_and_inspection_admission_coexists_with_serde_fallback() {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_depth(0);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let redactor = Redactor::new(policy);
        let value = Wrapper("visible".to_owned());

        let text = redactor.redact_text(&value);
        assert!(text.summary().reasons().contains(RedactionReason::DepthLimitReached));
        assert!(
            redactor
                .inspect(&value)
                .expect_err("depth zero must reject text inspection")
                .reasons()
                .contains(RedactionReason::DepthLimitReached)
        );
        assert_eq!(
            serde_json::to_string(&redactor.redact_view(&value)).expect("safe serde fallback"),
            "\"<redacted>\""
        );
    }
}
