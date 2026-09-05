#![cfg(all(feature = "derive", feature = "serde"))]

use std::collections::BTreeMap;
use std::sync::Mutex;

use qubit_redact::MaskPolicy;
use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact_derive::Redact;

static APPLICATION_DEFAULT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Redact)]
#[redact(serde)]
struct Child {
    #[redact(level = "secret")]
    token: String,
}

#[derive(Redact)]
#[redact(serde)]
struct Envelope {
    #[redact(nested)]
    child: Child,
    #[redact(nested)]
    children: Option<Vec<Child>>,
    #[redact(map)]
    headers: BTreeMap<String, String>,
    #[redact(skip)]
    hidden: String,
    #[redact(level = "secret")]
    levels: Vec<String>,
}

#[derive(Redact)]
#[redact(serde, debug, display)]
struct KeyedPair {
    key: String,
    #[redact(keyed_by = key)]
    value: Option<String>,
}

#[test]
fn serde_nested_and_map_modes_redact_structured_values() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("token");
            fields.secret_sensitive("authorization");
        })
        .expect("field policy")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));

    let mut headers = BTreeMap::new();
    headers.insert("authorization".to_owned(), "raw-header".to_owned());
    headers.insert("public".to_owned(), "visible".to_owned());
    let value = Envelope {
        child: Child {
            token: "raw-token".to_owned(),
        },
        children: Some(vec![Child {
            token: "raw-token-2".to_owned(),
        }]),
        headers,
        hidden: "hidden-value".to_owned(),
        levels: vec!["first".to_owned(), "second".to_owned()],
    };

    let encoded = serde_json::to_value(&value).expect("structured serialization");
    assert_ne!(encoded["child"]["token"], "raw-token");
    assert_ne!(encoded["children"][0]["token"], "raw-token-2");
    assert_ne!(encoded["headers"]["authorization"], "raw-header");
    assert_eq!(encoded["headers"]["public"], "visible");
    assert!(encoded.get("hidden").is_none());
    assert_ne!(encoded["levels"][0], "first");
    assert_ne!(encoded["levels"][1], "second");

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn serde_and_format_keyed_by_classify_value_by_sibling_key() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("password");
        })
        .expect("field policy")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));
    let secret = KeyedPair {
        key: "password".to_owned(),
        value: Some("raw-secret".to_owned()),
    };
    let public = KeyedPair {
        key: "region".to_owned(),
        value: Some("eu-west".to_owned()),
    };

    let debug = format!("{secret:?}");
    let display = format!("{secret}");
    let secret_json = serde_json::to_value(&secret).expect("secret keyed pair serialization");
    let public_json = serde_json::to_value(&public).expect("public keyed pair serialization");

    assert!(!debug.contains("raw-secret"));
    assert!(!display.contains("raw-secret"));
    assert_ne!(secret_json["value"], "raw-secret");
    assert_eq!(public_json["value"], "eu-west");

    let floor = RedactionFloor::builder()
        .raise("region", Sensitivity::High)
        .expect("floor field")
        .build()
        .expect("floor");
    let floored_policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.floor(floor).allow_exact("region");
        })
        .expect("floored field policy")
        .build()
        .expect("floored redaction policy");
    let _ = Redactor::replace_application_default(Redactor::new(floored_policy));
    let floored_json = serde_json::to_value(&public).expect("floored keyed pair serialization");
    assert_ne!(floored_json["value"], "eu-west");

    let _ = Redactor::replace_application_default(Redactor::new(RedactionPolicy::disabled()));
    let disabled_json = serde_json::to_value(&secret).expect("disabled keyed pair serialization");
    assert_eq!(disabled_json["value"], "raw-secret");

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn serde_disabled_mode_restores_level_map_and_skip_values() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let previous = Redactor::replace_application_default(Redactor::new(RedactionPolicy::disabled()));
    assert!(Redactor::application_default().policy().is_disabled());
    let mut headers = BTreeMap::new();
    headers.insert("authorization".to_owned(), "raw-header".to_owned());
    let value = Envelope {
        child: Child {
            token: "raw-token".to_owned(),
        },
        children: Some(vec![Child {
            token: "raw-token-2".to_owned(),
        }]),
        headers,
        hidden: "hidden-value".to_owned(),
        levels: vec!["first".to_owned(), "second".to_owned()],
    };

    let encoded = serde_json::to_value(&value).expect("structured serialization");
    assert_eq!(encoded["child"]["token"], "raw-token");
    assert_eq!(encoded["headers"]["authorization"], "raw-header");
    assert_eq!(encoded["hidden"], "hidden-value");
    assert_eq!(encoded["levels"][0], "first");
    assert_eq!(encoded["levels"][1], "second");

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn serde_structured_modes_share_depth_and_collection_budgets() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("token");
        })
        .expect("field policy")
        .limits(|limits| {
            limits.max_depth(1);
            limits.max_collection_items(1);
        })
        .expect("limits")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));

    let mut headers = BTreeMap::new();
    headers.insert("authorization".to_owned(), "raw-header".to_owned());
    let value = Envelope {
        child: Child {
            token: "raw-token".to_owned(),
        },
        children: Some(vec![Child {
            token: "raw-token-2".to_owned(),
        }]),
        headers,
        hidden: "hidden-value".to_owned(),
        levels: vec!["first".to_owned(), "second".to_owned()],
    };

    let encoded = serde_json::to_value(&value).expect("structured serialization");
    assert!(encoded["child"].is_string());
    assert!(encoded["levels"].is_string());
    assert!(!encoded.to_string().contains("raw-token"));

    let _ = Redactor::replace_application_default(previous);
}

#[cfg(feature = "json")]
#[derive(Redact)]
#[redact(serde)]
struct JsonEnvelope {
    #[redact(json)]
    payload: String,
}

#[cfg(feature = "json")]
#[test]
fn serde_json_mode_redacts_keyed_values_and_preserves_shape() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("token");
        })
        .expect("field policy")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));

    let value = JsonEnvelope {
        payload: r#"{"token":"raw-token","public":"visible"}"#.to_owned(),
    };
    let encoded = serde_json::to_value(&value).expect("structured JSON serialization");
    let payload = encoded["payload"]
        .as_str()
        .expect("JSON mode preserves the string wire type");
    let payload: serde_json::Value = serde_json::from_str(payload).expect("redacted JSON text remains valid");
    assert_ne!(payload["token"], "raw-token");
    assert_eq!(payload["public"], "visible");

    let _ = Redactor::replace_application_default(previous);
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

#[derive(Redact)]
#[redact(serde)]
struct PredicateEnvelope {
    #[redact(level = "secret")]
    #[serde(skip_serializing_if = "is_zero")]
    secret_number: u32,
    #[redact(skip)]
    #[serde(skip_serializing_if = "String::is_empty")]
    skipped_text: String,
}

#[derive(Redact)]
#[redact(serde)]
struct RecursiveMapEnvelope {
    #[redact(map)]
    values: BTreeMap<String, Option<Vec<(u32, String)>>>,
}

#[derive(Redact)]
#[redact(serde)]
struct InputBudgetEnvelope {
    #[redact(level = "low")]
    values: Vec<String>,
}

#[derive(Redact)]
#[redact(serde)]
struct InputBudgetMapEnvelope {
    #[redact(map)]
    values: BTreeMap<String, String>,
}

#[derive(Redact)]
#[redact(serde)]
struct InternalPayload {
    #[redact(level = "secret")]
    token: String,
    visible: String,
}

#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum InternallyTaggedEnvelope {
    Nested(#[redact(nested)] InternalPayload),
}

#[test]
fn serde_skip_predicates_observe_raw_values_for_every_redaction_mode() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let previous = Redactor::replace_application_default(Redactor::standard());
    let enabled = serde_json::to_value(PredicateEnvelope {
        secret_number: 0,
        skipped_text: "not-evaluated-while-redaction-is-enabled".to_owned(),
    })
    .expect("enabled structured serialization");
    assert!(enabled.get("secret_number").is_none());
    assert!(enabled.get("skipped_text").is_none());

    let _ = Redactor::replace_application_default(Redactor::new(RedactionPolicy::disabled()));
    let disabled = serde_json::to_value(PredicateEnvelope {
        secret_number: 7,
        skipped_text: String::new(),
    })
    .expect("disabled structured serialization");
    assert_eq!(disabled["secret_number"], 7);
    assert!(disabled.get("skipped_text").is_none());

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn serde_map_mode_masks_each_recursive_scalar_leaf() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("credential");
        })
        .expect("field policy")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));
    let value = RecursiveMapEnvelope {
        values: BTreeMap::from([
            ("credential".to_owned(), Some(vec![(7, "raw-secret".to_owned())])),
            ("public".to_owned(), Some(vec![(9, "shown".to_owned())])),
        ]),
    };

    let encoded = serde_json::to_value(&value).expect("recursive map serialization");
    assert!(encoded["values"]["credential"].is_array());
    assert_ne!(encoded["values"]["credential"][0][0], 7);
    assert_ne!(encoded["values"]["credential"][0][1], "raw-secret");
    assert_eq!(encoded["values"]["public"][0][0], 9);
    assert_eq!(encoded["values"]["public"][0][1], "shown");

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn test_serde_level_values_share_the_cumulative_input_budget() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.mask(Sensitivity::Low, MaskPolicy::preserve_edges(1, 1, "#", 0));
        })
        .expect("masking policy")
        .limits(|limits| {
            limits.max_input_bytes(5);
        })
        .expect("limits")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));
    let value = InputBudgetEnvelope {
        values: vec!["abc".to_owned(), "def".to_owned()],
    };

    let encoded = serde_json::to_value(&value).expect("structured serialization");
    assert_eq!(encoded["values"][0], "a#c");
    assert_eq!(encoded["values"][1], "<redacted>");

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn test_disabled_serde_level_values_still_enforce_the_input_budget() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_input_bytes(5);
        })
        .expect("limits")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));
    let value = InputBudgetEnvelope {
        values: vec!["abc".to_owned(), "def".to_owned()],
    };

    let encoded = serde_json::to_value(&value).expect("structured serialization");
    assert_eq!(encoded["values"][0], "abc");
    assert_eq!(encoded["values"][1], "<redacted>");

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn test_serde_map_values_share_the_cumulative_input_budget() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .low_sensitive("credential")
                .mask(Sensitivity::Low, MaskPolicy::preserve_edges(1, 1, "#", 0));
        })
        .expect("field policy")
        .limits(|limits| {
            limits.max_input_bytes(2);
        })
        .expect("limits")
        .build()
        .expect("redaction policy");
    let previous = Redactor::replace_application_default(Redactor::new(policy));
    let value = InputBudgetMapEnvelope {
        values: BTreeMap::from([("credential".to_owned(), "abc".to_owned())]),
    };

    let encoded = serde_json::to_value(&value).expect("structured serialization");
    assert_eq!(encoded["values"]["credential"], "<redacted>");

    let _ = Redactor::replace_application_default(previous);
}

#[test]
fn serde_internally_tagged_newtype_merges_redacted_payload_beside_tag() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let previous = Redactor::replace_application_default(Redactor::standard());
    let value = InternallyTaggedEnvelope::Nested(InternalPayload {
        token: "raw-token".to_owned(),
        visible: "shown".to_owned(),
    });

    let encoded = serde_json::to_value(&value).expect("internally tagged serialization");
    assert_eq!(encoded["kind"], "Nested");
    assert_ne!(encoded["token"], "raw-token");
    assert_eq!(encoded["visible"], "shown");
    assert!(encoded.get("payload").is_none());

    let _ = Redactor::replace_application_default(previous);
}

#[cfg(feature = "json")]
#[test]
fn serde_json_disabled_mode_keeps_json_text_as_text() {
    let _guard = APPLICATION_DEFAULT_LOCK.lock().expect("default lock");
    let previous = Redactor::replace_application_default(Redactor::new(RedactionPolicy::disabled()));
    let value = JsonEnvelope {
        payload: r#"{"token":"raw-token"}"#.to_owned(),
    };

    let encoded = serde_json::to_value(&value).expect("structured JSON serialization");
    assert_eq!(encoded["payload"], r#"{"token":"raw-token"}"#);

    let _ = Redactor::replace_application_default(previous);
}
