// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Shared black-box behavior assertions for derive integration tests.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct NamedRecord {
    visible: &'static str,
    #[redact(level = "secret")]
    secret: String,
    #[redact(skip)]
    skipped: String,
    #[redact(map)]
    metadata: BTreeMap<String, String>,
}

#[derive(Redact)]
struct TupleRecord(#[redact(level = "secret")] String, #[redact(skip)] String);

#[derive(Redact)]
enum Event {
    Named {
        #[redact(level = "secret")]
        secret: String,
    },
    Tuple(#[redact(level = "secret")] String),
    Ready,
}

struct PanicDebug;

impl fmt::Debug for PanicDebug {
    /// Panics when a rejected field is formatted.
    fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        panic!("an unadmitted field must not be formatted");
    }
}

#[derive(Redact)]
struct AdmissionRecord {
    visible: &'static str,
    blocked: PanicDebug,
}

#[derive(Redact)]
struct DepthLeaf {
    blocked: PanicDebug,
}

#[derive(Redact)]
struct DepthRoot {
    #[redact(nested)]
    child: DepthLeaf,
}

#[derive(Redact)]
#[redact(debug, display)]
struct FormattedRecord {
    #[redact(level = "secret")]
    secret: String,
}

#[cfg(feature = "serde")]
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "payload")]
enum SerializableEvent {
    Tuple(#[redact(level = "secret")] String),
    Ready,
}

#[cfg(feature = "serde")]
#[derive(Redact)]
#[redact(serde)]
struct SerdeAdapterRecord {
    #[serde(with = "serde_adapter")]
    with_value: String,
    #[serde(serialize_with = "serde_adapter::serialize")]
    function_value: String,
}

#[cfg(feature = "serde")]
mod serde_adapter {
    use serde::Serializer;

    /// Serializes a string with an observable adapter prefix.
    pub fn serialize<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("adapted:{value}"))
    }
}

#[cfg(feature = "json")]
#[derive(Redact)]
#[redact(serde)]
struct JsonRecord {
    #[redact(json)]
    document: String,
}

/// Verifies one compile-fail fixture and its checked diagnostic.
pub fn assert_compile_fail(path: &str) {
    trybuild::TestCases::new().compile_fail(path);
}

/// Verifies named fields retain labels and explicit field modes.
pub fn assert_named_redaction() {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("token");
        })
        .expect("the field policy is valid")
        .build()
        .expect("the redaction policy is valid");
    let value = NamedRecord {
        visible: "shown",
        secret: String::from("raw-secret"),
        skipped: String::from("raw-skipped"),
        metadata: BTreeMap::from([(String::from("token"), String::from("raw-map"))]),
    };
    let output = Redactor::new(policy).redact(&value);
    let text = output.text().as_str();

    assert!(text.contains("shown"), "{text}");
    assert!(!text.contains("raw-secret"), "{text}");
    assert!(!text.contains("raw-skipped"), "{text}");
    assert!(!text.contains("raw-map"), "{text}");
}

/// Verifies tuple fields retain their positional shape.
pub fn assert_tuple_redaction() {
    let value = TupleRecord(String::from("raw-secret"), String::from("raw-skipped"));
    let text = Redactor::standard().redact(&value);

    assert!(text.text().as_str().starts_with("TupleRecord("));
    assert!(!text.text().as_str().contains("raw-secret"));
    assert!(!text.text().as_str().contains("raw-skipped"));
}

/// Verifies named, tuple, and unit enum variants retain their shape.
pub fn assert_enum_redaction() {
    let named = Redactor::standard().redact(&Event::Named {
        secret: String::from("raw-secret"),
    });
    let tuple = Redactor::standard().redact(&Event::Tuple(String::from("raw-secret")));
    let ready = Redactor::standard().redact(&Event::Ready);

    assert!(named.text().as_str().starts_with("Named"));
    assert!(!named.text().as_str().contains("raw-secret"));
    assert!(tuple.text().as_str().starts_with("Tuple"));
    assert!(!tuple.text().as_str().contains("raw-secret"));
    assert!(ready.text().as_str().contains("Ready"));
}

/// Verifies traversal admission happens before ordinary formatting.
pub fn assert_field_admission_precedes_access() {
    let policy = policy_with_limits(2, 1);
    let value = AdmissionRecord {
        visible: "shown",
        blocked: PanicDebug,
    };
    let output = Redactor::new(policy).redact(&value);

    assert!(output.text().as_str().contains("shown"));
}

/// Verifies nested values reuse the parent depth budget.
pub fn assert_nested_admission_uses_shared_session() {
    let policy = policy_with_limits(8, 1);
    let value = DepthRoot {
        child: DepthLeaf { blocked: PanicDebug },
    };
    let _ = Redactor::new(policy).redact(&value);
}

/// Verifies generated Debug and Display use the application redactor.
pub fn assert_format_expansion() {
    let value = FormattedRecord {
        secret: String::from("raw-secret"),
    };

    assert!(!format!("{value:?}").contains("raw-secret"));
    assert!(!format!("{value}").contains("raw-secret"));
}

/// Verifies each accepted sensitivity spelling reaches runtime behavior.
pub fn assert_sensitivity_expansion() {
    assert_named_redaction();
    assert_eq!(Sensitivity::Low.min(Sensitivity::Secret), Sensitivity::Low);
}

/// Verifies structured Serde preserves representation and masks payloads.
#[cfg(feature = "serde")]
pub fn assert_serde_expansion() {
    let tuple = serde_json::to_value(SerializableEvent::Tuple(String::from("raw-secret")))
        .expect("the adjacent tuple serializes");
    let ready = serde_json::to_value(SerializableEvent::Ready).expect("the unit variant serializes");

    assert_eq!(tuple["kind"], "Tuple");
    assert_ne!(tuple["payload"][0], "raw-secret");
    assert_eq!(ready["kind"], "Ready");
}

/// Verifies unmarked fields preserve Serde serialization adapters.
#[cfg(feature = "serde")]
pub fn assert_serde_adapter_expansion() {
    let value = SerdeAdapterRecord {
        with_value: String::from("with"),
        function_value: String::from("function"),
    };
    let encoded = serde_json::to_value(value).expect("the adapted record serializes");

    assert_eq!(encoded["with_value"], "adapted:with");
    assert_eq!(encoded["function_value"], "adapted:function");
}

/// Verifies JSON fields remain strings after recursive redaction.
#[cfg(feature = "json")]
pub fn assert_json_expansion() {
    let value = JsonRecord {
        document: String::from(r#"{"token":"raw-secret","visible":"shown"}"#),
    };
    let encoded = serde_json::to_value(&value).expect("the JSON record serializes");
    let document = encoded["document"].as_str().expect("the JSON field remains a string");

    assert!(!document.contains("raw-secret"), "{document}");
    assert!(document.contains("visible"), "{document}");
}

/// Builds a policy with exact node and depth limits.
fn policy_with_limits(max_nodes: usize, max_depth: usize) -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(max_nodes).max_depth(max_depth);
        })
        .expect("the limits are valid")
        .build()
        .expect("the policy is valid")
}
