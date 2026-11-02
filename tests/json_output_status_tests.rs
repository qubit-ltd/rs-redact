// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(all(feature = "derive", feature = "json"))]

use std::cell::Cell;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionReasons;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::domain::internal::RedactSerializeSource;
use qubit_redact::domain::internal::RedactedLevelSerializeRef;
use serde::Serialize;
use serde::Serializer;

#[derive(Redact)]
struct Login {
    #[redact(level = "secret")]
    password: String,
}

#[test]
fn test_normal_mask_and_node_rejection_are_distinguishable() {
    let value = Login {
        password: "raw-secret".into(),
    };
    let normal = Redactor::standard().to_json_with_status(&value).unwrap();
    assert!(normal.is_complete());
    assert_eq!(normal.json(), r#"{"password":"<redacted>"}"#);
    assert_eq!(normal.json(), Redactor::standard().to_json(&value).unwrap());
    assert_eq!(normal.clone().into_json(), normal.json());
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(0);
        })
        .unwrap()
        .build()
        .unwrap();
    let limited = Redactor::new(policy).to_json_with_status(&value).unwrap();
    assert!(!limited.is_complete());
    assert!(limited.reasons().contains(RedactionReason::TraversalLimitReached));
    assert_eq!(limited.json(), r#""<redacted>""#);
    assert!(!limited.json().contains("raw-secret"));
}

#[derive(Redact)]
struct JsonRecord {
    #[redact(json)]
    payload: String,
}

#[derive(Redact)]
#[allow(clippy::vec_box)] // The boxes make this self-recursive derive fixture representable.
struct RecursiveNode {
    children: Vec<Box<RecursiveNode>>,
}

#[derive(Redact)]
struct LevelValues {
    #[redact(level = "low")]
    labels: Vec<String>,
    #[redact(level = "low")]
    text: String,
}

#[derive(Redact)]
struct SkipAndCondition {
    #[serde(skip_serializing)]
    hidden: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<String>,
    visible: u8,
}

struct CountedSource(Cell<usize>);
struct CountedProjection<'a>(&'a Cell<usize>);

impl RedactSerializeSource for CountedSource {
    type RedactedFields<'value> = CountedProjection<'value>;

    fn redacted_fields<'value>(&'value self, _: &RedactionPolicy) -> Self::RedactedFields<'value> {
        self.0.set(self.0.get() + 1);
        CountedProjection(&self.0)
    }
}

impl Serialize for CountedProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.set(self.0.get() + 1);
        serializer.serialize_u8(7)
    }
}

struct CollectionSource(Vec<String>);
struct CollectionProjection<'value>(&'value Vec<String>);

impl RedactSerializeSource for CollectionSource {
    type RedactedFields<'value> = CollectionProjection<'value>;

    fn redacted_fields<'value>(&'value self, _: &RedactionPolicy) -> Self::RedactedFields<'value> {
        CollectionProjection(&self.0)
    }
}

impl Serialize for CollectionProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let policy = qubit_redact::domain::internal::current_policy().expect("active structured redaction policy");
        RedactedLevelSerializeRef::new(self.0, &policy, Sensitivity::Low).serialize(serializer)
    }
}

#[test]
fn test_json_fallback_reports_invalid_json() {
    let json = Redactor::standard()
        .to_json_with_status(&JsonRecord {
            payload: "not-json".into(),
        })
        .unwrap();
    assert!(!json.is_complete());
    assert!(json.reasons().contains(RedactionReason::InvalidJson));
    assert!(!json.json().contains("not-json"));
}

#[test]
fn test_json_decoder_rejects_duplicate_keys_as_invalid_json() {
    let output = Redactor::standard()
        .to_json_with_status(&JsonRecord {
            payload: r#"{"key":1,"key":2}"#.into(),
        })
        .unwrap();
    assert!(!output.is_complete());
    assert!(output.reasons().contains(RedactionReason::InvalidJson));
    assert!(!output.json().contains(r#"{"key":1,"key":2}"#));
}

#[test]
fn test_json_resource_fallback_reports_traversal_reason() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1);
        })
        .unwrap()
        .build()
        .unwrap();
    let output = Redactor::new(policy)
        .to_json_with_status(&JsonRecord { payload: "[0]".into() })
        .unwrap();
    assert!(!output.is_complete());
    assert!(output.reasons().contains(RedactionReason::TraversalLimitReached));
    assert!(!output.json().contains("[0]"));
}

#[test]
fn test_status_is_per_call_after_success_and_error() {
    let good = Login {
        password: "raw-secret".into(),
    };
    let standard = Redactor::standard();
    assert!(standard.to_json_with_status(&good).unwrap().is_complete());
    let limited = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(0);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    assert!(!limited.to_json_with_status(&good).unwrap().is_complete());
    assert!(standard.to_json_with_status(&good).unwrap().is_complete());

    let no_output = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_output_bytes(0);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    assert!(no_output.to_json_with_status(&good).is_err());

    let no_payload = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_serde_payload_bytes(0);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    assert!(no_payload.to_json_with_status(&good).is_err());
    assert!(standard.to_json_with_status(&good).unwrap().is_complete());
}

#[test]
fn test_recursive_depth_fallback_reports_reason() {
    let value = RecursiveNode {
        children: vec![Box::new(RecursiveNode { children: Vec::new() })],
    };
    let depth_limited = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_depth(1);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    let depth = depth_limited.to_json_with_status(&value).unwrap();
    assert!(!depth.is_complete());
    assert!(depth.reasons().contains(RedactionReason::DepthLimitReached));
    assert_eq!(depth.json(), r#"{"children":"<redacted>"}"#);
}

#[test]
fn test_collection_fallback_and_exact_admission_boundary() {
    let value = CollectionSource(vec!["one".into()]);
    let limited = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_collection_items(0);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    let fallback = limited.to_json_with_status(&value).unwrap();
    assert!(!fallback.is_complete());
    assert!(fallback.reasons().contains(RedactionReason::TraversalLimitReached));
    assert_eq!(fallback.json(), r#""<redacted>""#);
    assert!(!fallback.json().contains("one"));

    let exact = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_collection_items(1);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    let complete = exact.to_json_with_status(&value).unwrap();
    assert!(complete.is_complete());
    assert_eq!(complete.reasons(), RedactionReasons::empty());
}

#[test]
fn test_input_limit_skip_disabled_and_one_pass_status() {
    let value = LevelValues {
        labels: Vec::new(),
        text: "four".into(),
    };
    let limited = Redactor::new(
        RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_input_bytes(3);
            })
            .unwrap()
            .build()
            .unwrap(),
    );
    let masked = limited.to_json_with_status(&value).unwrap();
    assert!(!masked.is_complete());
    assert!(masked.reasons().contains(RedactionReason::InputLimitReached));
    assert!(!masked.json().contains("four"));

    let skipped = Redactor::standard()
        .to_json_with_status(&SkipAndCondition {
            hidden: "must-not-appear".into(),
            optional: None,
            visible: 7,
        })
        .unwrap();
    assert!(skipped.is_complete());
    assert_eq!(skipped.json(), r#"{"visible":7}"#);

    let disabled = Redactor::new(RedactionPolicy::disabled())
        .to_json_with_status(&Login {
            password: "raw-secret".into(),
        })
        .unwrap();
    assert!(disabled.is_complete());
    assert!(disabled.json().contains("raw-secret"));

    let source = CountedSource(Cell::new(0));
    let single_pass = Redactor::standard().to_json_with_status(&source).unwrap();
    assert!(single_pass.is_complete());
    assert_eq!(single_pass.json(), "7");
    assert_eq!(source.0.get(), 2); // one projection plus one projection serialization callback
}
// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
