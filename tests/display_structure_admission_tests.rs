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
use qubit_redact::domain::internal::RedactSerialize;

struct Counted<'a>(&'a Cell<usize>);

impl fmt::Display for Counted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        f.write_str("visible")
    }
}

#[derive(Redact)]
#[redact(serde)]
struct LowRecord<'a> {
    #[redact(display, level = "low")]
    value: Counted<'a>,
}

#[derive(Redact)]
#[redact(serde)]
struct MediumRecord<'a> {
    #[redact(display, level = "medium")]
    value: Counted<'a>,
}

struct SecretCounted<'a>(&'a Cell<usize>);

impl fmt::Display for SecretCounted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        f.write_str("secret")
    }
}

#[derive(Redact)]
#[redact(serde)]
struct SecretRecord<'a> {
    #[redact(display, level = "secret")]
    value: SecretCounted<'a>,
}

#[derive(Redact)]
#[redact(serde)]
struct HighRecord<'a> {
    #[redact(display, level = "high")]
    value: Counted<'a>,
}

fn limited_policy(max_nodes: usize, max_depth: usize, disabled: bool) -> RedactionPolicy {
    let builder = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(max_nodes);
            limits.max_depth(max_depth);
        })
        .expect("valid limits");
    let mut policy = builder.build().expect("valid policy");
    let _ = policy.set_disabled(disabled);
    policy
}

#[test]
fn test_display_node_rejection_precedes_formatter() {
    let calls = Cell::new(0);
    let record = LowRecord { value: Counted(&calls) };
    let policy = limited_policy(1, 8, false);

    let source = record
        .serialize_redacted(serde_json::value::Serializer, &policy)
        .expect("safe source replacement");
    assert_eq!(source["value"], "<redacted>");
    let view = serde_json::to_value(Redactor::new(policy).redact_view(&record)).expect("safe view replacement");
    assert_eq!(view["value"], "<redacted>");
    assert_eq!(calls.get(), 0);
}

#[test]
fn test_display_node_and_depth_admission_matrix() {
    for (max_nodes, max_depth, admitted) in [(1, 8, false), (2, 8, true), (8, 1, false), (8, 2, true)] {
        for disabled in [false, true] {
            for source_path in [false, true] {
                let calls = Cell::new(0);
                let record = LowRecord { value: Counted(&calls) };
                let policy = limited_policy(max_nodes, max_depth, disabled);
                let encoded = if source_path {
                    record
                        .serialize_redacted(serde_json::value::Serializer, &policy)
                        .expect("source serialization")
                } else {
                    serde_json::to_value(Redactor::new(policy).redact_view(&record)).expect("view serialization")
                };
                let expected = match (admitted, disabled) {
                    (true, true) => "visible",
                    (true, false) => "vi****le",
                    (false, _) => "<redacted>",
                };
                assert_eq!(encoded["value"], expected);
                assert_eq!(calls.get(), usize::from(admitted));
            }
        }
    }
}

#[test]
fn test_display_secret_never_calls_formatter() {
    let calls = Cell::new(0);
    let record = SecretRecord {
        value: SecretCounted(&calls),
    };
    let policy = limited_policy(2, 2, false);
    let encoded = record
        .serialize_redacted(serde_json::value::Serializer, &policy)
        .expect("secret replacement");
    assert_eq!(encoded["value"], "<redacted>");
    assert_eq!(calls.get(), 0);
}

#[test]
fn test_display_high_never_calls_formatter() {
    let calls = Cell::new(0);
    let record = HighRecord { value: Counted(&calls) };
    let policy = limited_policy(2, 2, false);
    let encoded = record
        .serialize_redacted(serde_json::value::Serializer, &policy)
        .expect("high sensitivity replacement");
    assert_eq!(encoded["value"], "****");
    assert_eq!(calls.get(), 0);
}

#[test]
fn test_display_medium_formats_once_when_admitted() {
    for source_path in [false, true] {
        let calls = Cell::new(0);
        let record = MediumRecord { value: Counted(&calls) };
        let policy = limited_policy(2, 2, true);
        let encoded = if source_path {
            record
                .serialize_redacted(serde_json::value::Serializer, &policy)
                .expect("admitted source serialization")
        } else {
            serde_json::to_value(Redactor::new(policy).redact_view(&record)).expect("admitted view serialization")
        };
        assert_eq!(encoded["value"], "visible");
        assert_eq!(calls.get(), 1);
    }
}

#[test]
fn test_display_root_rejection_precedes_formatter() {
    let calls = Cell::new(0);
    let record = LowRecord { value: Counted(&calls) };
    let policy = limited_policy(0, 0, false);
    let encoded = record
        .serialize_redacted(serde_json::value::Serializer, &policy)
        .expect("safe root replacement");
    assert_eq!(encoded, "<redacted>");
    assert_eq!(calls.get(), 0);
}

#[cfg(feature = "json")]
#[test]
fn test_display_node_rejection_matches_json_output() {
    let calls = Cell::new(0);
    let record = LowRecord { value: Counted(&calls) };
    let policy = limited_policy(1, 8, false);
    assert_eq!(
        Redactor::new(policy).to_json(&record).expect("safe JSON replacement"),
        r#"{"value":"<redacted>"}"#
    );
    assert_eq!(calls.get(), 0);
}
