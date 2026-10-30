// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Option projections participate in structured Serde admission.

#![cfg(all(feature = "derive", feature = "serde"))]

use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use qubit_redact::Redact;
use qubit_redact::RedactSerialize;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::domain::internal::RedactSerializeSource;

static CHILD_SERIALIZATION_CALLS: AtomicUsize = AtomicUsize::new(0);

struct CountedChild;

impl RedactSerialize for CountedChild {
    fn serialize_redacted<S>(&self, serializer: S, _policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        CHILD_SERIALIZATION_CALLS.fetch_add(1, Ordering::SeqCst);
        serializer.serialize_unit()
    }
}

#[test]
fn test_legacy_none_obeys_zero_structural_budgets() {
    for limited in [
        policy(Some(0), None),
        policy(None, Some(0)),
        bounded_policy(RedactionPolicy::disabled(), Some(0), None),
        bounded_policy(RedactionPolicy::disabled(), None, Some(0)),
    ] {
        let value = None::<Empty>
            .serialize_redacted(serde_json::value::Serializer, &limited)
            .expect("safe legacy Option replacement");
        assert_eq!(value, serde_json::json!("<redacted>"));
    }
}

#[test]
fn test_legacy_option_layers_consume_nodes_and_depth() {
    let source = Some(Some(Empty {}));
    for limited in [policy(Some(2), None), policy(None, Some(2))] {
        assert_eq!(
            source
                .serialize_redacted(serde_json::value::Serializer, &limited)
                .unwrap(),
            serde_json::json!("<redacted>")
        );
    }
    for enough in [policy(Some(3), None), policy(None, Some(3))] {
        assert_eq!(
            source
                .serialize_redacted(serde_json::value::Serializer, &enough)
                .unwrap(),
            serde_json::json!({})
        );
    }
    assert_eq!(
        source
            .serialize_redacted(serde_json::value::Serializer, &RedactionPolicy::standard())
            .unwrap(),
        serde_json::json!({})
    );
}

#[test]
fn test_legacy_option_rejection_does_not_serialize_child() {
    CHILD_SERIALIZATION_CALLS.store(0, Ordering::SeqCst);
    let value = Some(CountedChild)
        .serialize_redacted(serde_json::value::Serializer, &policy(Some(0), None))
        .unwrap();
    assert_eq!(value, serde_json::json!("<redacted>"));
    assert_eq!(CHILD_SERIALIZATION_CALLS.load(Ordering::SeqCst), 0);
}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct Empty {}

#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct Credential {
    #[redact(level = "secret")]
    password: String,
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("intentional writer failure"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn policy(nodes: Option<usize>, depth: Option<usize>) -> RedactionPolicy {
    bounded_policy(RedactionPolicy::standard(), nodes, depth)
}

fn bounded_policy(base: RedactionPolicy, nodes: Option<usize>, depth: Option<usize>) -> RedactionPolicy {
    base.to_builder()
        .limits(|limits| {
            if let Some(nodes) = nodes {
                limits.max_nodes(nodes);
            }
            if let Some(depth) = depth {
                limits.max_depth(depth);
            }
        })
        .expect("limits")
        .build()
        .expect("policy")
}

#[test]
fn test_none_obeys_zero_node_and_depth_budgets() {
    for limited in [
        policy(Some(0), None),
        policy(None, Some(0)),
        bounded_policy(RedactionPolicy::disabled(), Some(0), None),
        bounded_policy(RedactionPolicy::disabled(), None, Some(0)),
    ] {
        let output =
            serde_json::to_value(Redactor::new(limited).redact_view(&None::<Empty>)).expect("safe Option replacement");
        assert_eq!(output, serde_json::json!("<redacted>"));
    }
}

#[test]
fn test_option_layers_consume_nodes_and_depth() {
    for limited in [policy(Some(2), None), policy(None, Some(2))] {
        let redactor = Redactor::new(limited);
        assert_eq!(
            serde_json::to_value(redactor.redact_view(&Some(Empty {}))).unwrap(),
            serde_json::json!({})
        );
        assert_eq!(
            serde_json::to_value(redactor.redact_view(&Some(Some(Empty {})))).unwrap(),
            serde_json::json!("<redacted>")
        );
    }
    for enough in [policy(Some(3), None), policy(None, Some(3))] {
        assert_eq!(
            serde_json::to_value(Redactor::new(enough).redact_view(&Some(Some(Empty {})))).unwrap(),
            serde_json::json!({})
        );
    }
}

#[test]
fn test_option_budget_preserves_secret_masking_for_source_view_and_json() {
    let source = Some(Credential {
        password: "raw-secret".into(),
    });
    let redactor = Redactor::standard();
    assert_eq!(
        serde_json::to_value(redactor.redact_view(&source)).unwrap()["password"],
        "<redacted>"
    );
    assert_eq!(serde_json::to_value(&source).unwrap()["password"], "<redacted>");
}

#[test]
fn test_option_projection_preserves_none_some_events_and_requires_scope() {
    let redactor = Redactor::standard();
    serde_test::assert_ser_tokens(&redactor.redact_view(&None::<Empty>), &[serde_test::Token::None]);
    serde_test::assert_ser_tokens(
        &redactor.redact_view(&Some(Empty {})),
        &[
            serde_test::Token::Some,
            serde_test::Token::Struct { name: "Empty", len: 0 },
            serde_test::Token::StructEnd,
        ],
    );

    for option in [None, Some(Empty {})] {
        let error = serde_json::to_string(&option.redacted_fields(&RedactionPolicy::standard()))
            .expect_err("bare Option projection requires scope");
        assert!(error.to_string().contains("active redaction scope"));
    }
}

#[test]
fn test_option_scope_recovers_after_serializer_error() {
    let redactor = Redactor::standard();
    let error = serde_json::to_writer(FailingWriter, &redactor.redact_view(&Some(Empty {})))
        .expect_err("writer error should propagate");
    assert!(error.to_string().contains("intentional writer failure"));

    assert_eq!(
        serde_json::to_value(redactor.redact_view(&Some(Empty {}))).unwrap(),
        serde_json::json!({})
    );
}

#[cfg(feature = "json")]
#[test]
fn test_option_budget_preserves_secret_masking_in_json_hook() {
    let source = Some(Credential {
        password: "raw-secret".into(),
    });
    assert!(Redactor::standard().to_json(&source).unwrap().contains("<redacted>"));
}
