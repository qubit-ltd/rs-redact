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
#[cfg(feature = "json")]
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use qubit_redact::Redact;
use qubit_redact::RedactSerialize;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
#[cfg(feature = "json")]
use qubit_redact::domain::internal::RedactJsonSerialize;
use qubit_redact::domain::internal::RedactSerializeSource;

static CHILD_SERIALIZATION_CALLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "json")]
static APPLICATION_DEFAULT_LOCK: Mutex<()> = Mutex::new(());

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

#[cfg(feature = "json")]
impl RedactJsonSerialize for CountedChild {
    fn serialize_redacted_json<S>(&self, serializer: S, _policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
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

#[cfg(feature = "json")]
#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct JsonOptional {
    #[redact(json)]
    value: Option<Option<serde_json::Value>>,
}

#[cfg(feature = "json")]
#[derive(Redact)]
#[redact(crate = qubit_redact, serde)]
struct JsonText {
    #[redact(json)]
    value: String,
}

#[cfg(feature = "json")]
struct JsonHook<'a, T> {
    source: &'a T,
    policy: &'a RedactionPolicy,
}

#[cfg(feature = "json")]
impl<T: RedactJsonSerialize> serde::Serialize for JsonHook<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.source.serialize_redacted_json(serializer, self.policy)
    }
}

#[cfg(feature = "json")]
struct ApplicationDefaultRestore(Redactor);

#[cfg(feature = "json")]
impl Drop for ApplicationDefaultRestore {
    fn drop(&mut self) {
        let _ = Redactor::replace_application_default(self.0.clone());
    }
}

#[cfg(feature = "json")]
#[test]
fn test_json_option_layers_obey_node_depth_and_recover_across_entries() {
    let _lock = APPLICATION_DEFAULT_LOCK.lock().expect("application-default test lock");
    let original = Redactor::application_default();
    let _restore = ApplicationDefaultRestore(original.clone());
    let source = JsonOptional { value: Some(None) };

    for (nodes, depth, enough) in [(Some(1), None, Some(2)), (None, Some(1), Some(2))] {
        let output = Redactor::new(policy(nodes, depth))
            .to_json(&JsonOptional { value: None })
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap()["value"],
            "<redacted>"
        );
        let output = Redactor::new(policy(enough, None))
            .to_json(&JsonOptional { value: None })
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap()["value"],
            serde_json::Value::Null
        );
    }

    for (nodes, depth) in [(Some(1), None), (Some(2), None), (None, Some(1)), (None, Some(2))] {
        let limited = policy(nodes, depth);
        let output = Redactor::new(limited.clone())
            .to_json(&source)
            .expect("safe replacement fits");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap()["value"],
            "<redacted>"
        );
        assert_eq!(
            serde_json::to_value(Redactor::new(limited.clone()).redact_view(&source)).unwrap()["value"],
            "<redacted>"
        );

        let _ = Redactor::replace_application_default(Redactor::new(limited));
        let output = serde_json::to_value(&source).expect("safe replacement fits");
        assert_eq!(output["value"], "<redacted>");
    }

    for enough in [policy(Some(3), None), policy(None, Some(3))] {
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&Redactor::new(enough.clone()).to_json(&source).unwrap())
                .unwrap()["value"],
            serde_json::Value::Null
        );
        assert_eq!(
            serde_json::to_value(Redactor::new(enough.clone()).redact_view(&source)).unwrap()["value"],
            serde_json::Value::Null
        );
        let _ = Redactor::replace_application_default(Redactor::new(enough));
        assert_eq!(serde_json::to_value(&source).unwrap()["value"], serde_json::Value::Null);
    }

    for (nodes, depth) in [(Some(1), None), (None, Some(1))] {
        let limited = bounded_policy(RedactionPolicy::disabled(), nodes, depth);
        let redactor = Redactor::new(limited.clone());
        assert_eq!(
            serde_json::to_value(redactor.redact_view(&source)).unwrap()["value"],
            "<redacted>"
        );
        let output = redactor.to_json(&source).expect("safe replacement fits");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap()["value"],
            "<redacted>"
        );
        let _ = Redactor::replace_application_default(Redactor::new(limited));
        assert_eq!(serde_json::to_value(&source).unwrap()["value"], "<redacted>");
    }
    let disabled_enough = bounded_policy(RedactionPolicy::disabled(), Some(3), Some(3));
    let disabled_redactor = Redactor::new(disabled_enough);
    assert_eq!(
        serde_json::to_value(disabled_redactor.redact_view(&source)).unwrap()["value"],
        serde_json::Value::Null
    );
    let output = disabled_redactor
        .to_json(&source)
        .expect("disabled JSON value serializes");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).unwrap()["value"],
        serde_json::Value::Null
    );
    let _ = Redactor::replace_application_default(disabled_redactor);
    assert_eq!(serde_json::to_value(&source).unwrap()["value"], serde_json::Value::Null);

    for option in [None, Some(None)] {
        let policy = policy(Some(3), Some(3));
        let output = Redactor::new(policy)
            .to_json(&JsonOptional { value: option.clone() })
            .unwrap();
        let value: serde_json::Value = serde_json::from_str(&output).unwrap();
        match option {
            None => assert_eq!(value["value"], serde_json::Value::Null),
            Some(None) => assert_eq!(value["value"], serde_json::Value::Null),
            _ => unreachable!(),
        }
    }
}

#[cfg(feature = "json")]
#[test]
fn test_disabled_json_text_consumes_structural_node_and_depth() {
    let _lock = APPLICATION_DEFAULT_LOCK.lock().expect("application-default test lock");
    let original = Redactor::application_default();
    let _restore = ApplicationDefaultRestore(original);
    let source = JsonText {
        value: "{\"safe\":true}".into(),
    };
    for limited in [
        bounded_policy(RedactionPolicy::disabled(), Some(1), None),
        bounded_policy(RedactionPolicy::disabled(), None, Some(1)),
    ] {
        let redactor = Redactor::new(limited.clone());
        assert_eq!(
            serde_json::to_value(redactor.redact_view(&source)).unwrap()["value"],
            "<redacted>"
        );
        let output = redactor.to_json(&source).expect("replacement fits");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap()["value"],
            "<redacted>"
        );
        let _ = Redactor::replace_application_default(Redactor::new(limited));
        assert_eq!(serde_json::to_value(&source).unwrap()["value"], "<redacted>");
    }
    for (nodes, depth) in [(Some(2), None), (None, Some(2))] {
        let redactor = Redactor::new(bounded_policy(RedactionPolicy::disabled(), nodes, depth));
        assert_eq!(
            serde_json::to_value(redactor.redact_view(&source)).unwrap()["value"],
            "{\"safe\":true}"
        );
        let output = redactor.to_json(&source).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap()["value"],
            "{\"safe\":true}"
        );
        let _ = Redactor::replace_application_default(redactor);
        assert_eq!(serde_json::to_value(&source).unwrap()["value"], "{\"safe\":true}");
    }
}

#[cfg(feature = "json")]
#[test]
fn test_json_option_hook_preserves_none_some_events_and_skips_rejected_child() {
    let standard_policy = RedactionPolicy::standard();
    serde_test::assert_ser_tokens(
        &JsonHook {
            source: &None::<String>,
            policy: &standard_policy,
        },
        &[serde_test::Token::None],
    );
    serde_test::assert_ser_tokens(
        &JsonHook {
            source: &Some("null".to_owned()),
            policy: &standard_policy,
        },
        &[serde_test::Token::Some, serde_test::Token::Str("null")],
    );

    CHILD_SERIALIZATION_CALLS.store(0, Ordering::SeqCst);
    let rejected = Some(CountedChild)
        .serialize_redacted_json(serde_json::value::Serializer, &policy(Some(0), None))
        .expect("safe replacement serializes");
    assert_eq!(rejected, serde_json::json!("<redacted>"));
    assert_eq!(CHILD_SERIALIZATION_CALLS.load(Ordering::SeqCst), 0);
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

    #[cfg(feature = "json")]
    {
        let json_source = JsonOptional { value: Some(None) };
        let json_redactor = Redactor::new(policy(Some(3), Some(3)));
        let error = serde_json::to_writer(FailingWriter, &json_redactor.redact_view(&json_source))
            .expect_err("writer error should propagate through the JSON hook");
        assert!(error.to_string().contains("intentional writer failure"));
        let output = json_redactor
            .to_json(&json_source)
            .expect("scope recovers after writer error");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap()["value"],
            serde_json::Value::Null
        );
    }
}

#[cfg(feature = "json")]
#[test]
fn test_option_budget_preserves_secret_masking_in_json_hook() {
    let source = Some(Credential {
        password: "raw-secret".into(),
    });
    assert!(Redactor::standard().to_json(&source).unwrap().contains("<redacted>"));
}
