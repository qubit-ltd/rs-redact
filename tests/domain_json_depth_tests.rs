// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "json")]

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use serde_json::Value;
use serde_json::json;

enum Parsed<'a> {
    Value(&'a Value),
    Text(&'a str),
    Sequence(&'a [Value]),
}

impl Redact for Parsed<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        match self {
            Self::Value(value) => writer.record("Parsed", |fields| {
                fields.json_value("Json", value);
            }),
            Self::Text(text) => writer.record("Parsed", |fields| {
                fields.json("Json", text);
            }),
            Self::Sequence(values) => writer.sequence(|items| {
                for value in *values {
                    items.json_value_item(value);
                }
            }),
        }
    }
}

struct Wrapper<'a>(Parsed<'a>);

impl Redact for Wrapper<'_> {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.tuple("Wrapper", |fields| {
            fields.nested("item", &self.0);
        });
    }
}

struct DomainChild(DomainGrandchild);

impl Redact for DomainChild {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Child", |fields| {
            fields.nested("grandchild", &self.0);
        });
    }
}

struct DomainGrandchild;

impl Redact for DomainGrandchild {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Grandchild", |_| {});
    }
}

struct DomainRoot(DomainChild);

impl Redact for DomainRoot {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Root", |fields| {
            fields.nested("child", &self.0);
        });
    }
}

fn redactor(max_depth: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(max_depth);
        })
        .expect("depth limit should be valid")
        .build()
        .expect("policy should build");
    Redactor::new(policy)
}

#[test]
fn test_domain_json_depth_is_continuous_across_value_text_and_sequence() {
    let value = json!({"visible": "shown", "password": "raw-secret"});
    let values = [value.clone()];
    let text = r#"{"visible":"shown","password":"raw-secret"}"#;
    let redactor = redactor(3);

    for parsed in [Parsed::Value(&value), Parsed::Text(text), Parsed::Sequence(&values)] {
        let wrapper = Wrapper(parsed);
        let inspection = redactor.inspect(&wrapper);
        assert!(
            inspection
                .as_ref()
                .is_err_and(|error| error.reasons().contains(RedactionReason::DepthLimitReached)),
            "inspection should reject JSON whose effective depth exceeds three"
        );

        let output = redactor.redact_text(&wrapper);
        assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
        assert!(output.summary().reasons().contains(RedactionReason::DepthLimitReached));
        assert!(!output.text().as_str().contains("raw-secret"));
        assert!(output.summary().usage().max_depth() <= 3);

        let composed = redactor.text_composer().value(&wrapper).finish();
        assert_eq!(composed.summary().completion(), RedactionCompletion::Truncated);
        assert!(
            composed
                .summary()
                .reasons()
                .contains(RedactionReason::DepthLimitReached)
        );
        assert!(!composed.text().as_str().contains("raw-secret"));

        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_value(&wrapper);
        let batch = batch.finish_with_marker("");
        assert_eq!(batch.summary().completion(), RedactionCompletion::Truncated);
        assert!(batch.summary().reasons().contains(RedactionReason::DepthLimitReached));
        assert!(!batch.text(handle).as_str().contains("raw-secret"));
    }
}

#[test]
fn test_domain_json_depth_usage_reports_combined_depth_and_top_level_json_is_unchanged() {
    let value = json!({"visible": "shown", "password": "raw-secret"});
    let wrapper = Wrapper(Parsed::Value(&value));
    let accepted = redactor(4).redact_text(&wrapper);
    assert_eq!(accepted.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(accepted.summary().usage().max_depth(), 4);

    let top_level = redactor(2).redact_json_value(&value);
    assert_eq!(top_level.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(top_level.summary().usage().max_depth(), 2);

    let control = redactor(3).redact_text(&DomainRoot(DomainChild(DomainGrandchild)));
    assert_eq!(control.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(control.summary().usage().max_depth(), 3);

    let zero_limit = redactor(0).redact_text(&wrapper);
    assert_eq!(zero_limit.summary().completion(), RedactionCompletion::Truncated);
    assert!(
        zero_limit
            .summary()
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );

    let redactor = redactor(4);
    let mut batch = redactor.diagnostic_batch();
    let first = batch.redact_value(&wrapper);
    let second = batch.redact_value(&wrapper);
    let batch = batch.finish_with_marker("");
    assert_eq!(batch.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(batch.summary().usage().max_depth(), 4);
    assert_eq!(batch.text(first).as_str(), batch.text(second).as_str());
}

#[test]
fn test_domain_json_depth_reports_combined_usage_with_maximum_shared_limit() {
    let value = json!({"visible": "shown", "password": "raw-secret"});
    let wrapper = Wrapper(Parsed::Value(&value));

    let output = redactor(usize::MAX).redact_text(&wrapper);

    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.summary().usage().max_depth(), 4);
}
