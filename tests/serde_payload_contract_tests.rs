// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Independent logical payload and final JSON byte contracts.

#![cfg(all(feature = "derive", feature = "serde", feature = "json"))]

use std::cell::Cell;
use std::fmt;

use qubit_redact::PolicyError;
use qubit_redact::Redact;
use qubit_redact::RedactionLimits;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeSeq;

#[derive(Redact)]
struct Plain<'a> {
    value: &'a str,
}

fn bounded(payload: usize, output: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_serde_payload_bytes(payload).max_output_bytes(output);
        })
        .expect("valid draft")
        .build()
        .expect("valid policy");
    Redactor::new(policy)
}

#[test]
fn test_external_serde_has_payload_limit_but_no_final_encoding_limit() {
    let value = Plain { value: "abcd" };
    let redactor = bounded(4, 4);
    let json = serde_json::to_string(&redactor.redact_view(&value)).expect("four payload bytes");
    assert_eq!(json, r#"{"value":"abcd"}"#);
    assert!(redactor.to_json(&value).is_err());
}

#[test]
fn test_rejected_payload_does_not_poison_a_later_scope() {
    let value = Plain { value: "abcd" };
    let redactor = bounded(3, 128);
    assert!(serde_json::to_string(&redactor.redact_view(&value)).is_err());
    assert!(redactor.to_json(&value).is_err());
    let smaller = Plain { value: "abc" };
    assert_eq!(redactor.to_json(&smaller).expect("fresh scope"), r#"{"value":"abc"}"#);
    assert!(bounded(4, 128).to_json(&value).is_ok());
}

#[test]
fn test_final_json_counts_labels_escaping_and_utf8() {
    let value = Plain { value: "é\n\"" };
    let expected = r#"{"value":"é\n\""}"#;
    assert_eq!(
        bounded(4, expected.len()).to_json(&value).expect("exact bound"),
        expected
    );
    assert!(bounded(4, expected.len() - 1).to_json(&value).is_err());
}

#[test]
fn test_zero_payload_allows_empty_scalar_but_rejects_nonempty_scalar() {
    let redactor = bounded(0, 128);
    assert_eq!(
        redactor.to_json(&Plain { value: "" }).expect("empty scalar"),
        r#"{"value":""}"#
    );
    assert!(redactor.to_json(&Plain { value: "x" }).is_err());
    assert!(bounded(0, 0).to_json(&Plain { value: "" }).is_err());
}

#[test]
fn test_payload_default_and_invalid_capacity_are_explicit() {
    assert_eq!(RedactionLimits::default().max_serde_payload_bytes(), 16 * 1024);
    let maximum = isize::MAX as usize + 1;
    let result = RedactionPolicy::builder().limits(|limits| {
        limits.max_serde_payload_bytes(maximum);
    });
    let error = result.expect_err("unaddressable payload limit");
    assert_eq!(error, PolicyError::SerdePayloadLimitTooLarge { maximum });
    assert!(error.to_string().contains("payload"));
}

#[derive(Debug)]
struct Counted<'a>(&'a Cell<usize>);

impl Serialize for Counted<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.set(self.0.get() + 1);
        serializer.serialize_str("abcd")
    }
}

#[derive(Redact)]
struct Observed<'a> {
    value: Counted<'a>,
}

#[test]
fn test_json_convenience_serializes_once_under_independent_limits() {
    for (payload, output, succeeds) in [(4, 16, true), (4, 15, false), (3, 128, false)] {
        let calls = Cell::new(0);
        let value = Observed { value: Counted(&calls) };
        assert_eq!(bounded(payload, output).to_json(&value).is_ok(), succeeds);
        assert_eq!(calls.get(), 1);
    }
}

#[derive(Debug)]
struct IgnoresWriteError;

impl fmt::Display for IgnoresWriteError {
    fn fmt(&self, writer: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = writer.write_str("oversized");
        let _ = writer.write_str("x");
        Ok(())
    }
}

impl Serialize for IgnoresWriteError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Redact)]
struct Collected {
    value: IgnoresWriteError,
}

#[test]
fn test_serde_collect_str_cannot_hide_payload_rejection() {
    let value = Collected {
        value: IgnoresWriteError,
    };
    let error = bounded(1, 128).to_json(&value).expect_err("latched payload failure");
    assert!(error.to_string().contains("payload"));
}

/// Attempts to finish a sequence after an element was rejected by the sink.
#[derive(Debug)]
struct IgnoresElementError;

impl Serialize for IgnoresElementError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(1))?;
        let _ = sequence.serialize_element("a payload far larger than the final output allowance");
        sequence.end()
    }
}

#[derive(Redact)]
struct IgnoredElement {
    value: IgnoresElementError,
}

#[test]
fn test_final_json_rejection_cannot_be_hidden_by_a_custom_serializer() {
    let value = IgnoredElement {
        value: IgnoresElementError,
    };
    assert!(bounded(128, 128).to_json(&value).is_ok());
    assert!(
        bounded(128, 16).to_json(&value).is_err(),
        "a rejected encoded chunk must prevent publication"
    );
}
