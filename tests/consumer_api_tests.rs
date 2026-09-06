//! Consumer-facing view, text, and structured serialization contracts.

#![cfg(all(feature = "derive", feature = "serde", feature = "json"))]

use std::cell::Cell;

use qubit_redact::Redact;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;

#[derive(Redact)]
#[redact(serde)]
struct Login {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

#[derive(Redact, serde::Serialize)]
struct StandardSerdeLogin {
    user: String,
    #[redact(level = "secret")]
    password: String,
}

#[test]
fn test_view_redacts_without_replacing_standard_serde() {
    let login = StandardSerdeLogin {
        user: "ada".into(),
        password: "raw-secret".into(),
    };
    assert_eq!(
        serde_json::to_value(&login).expect("standard serialization"),
        serde_json::json!({"user": "ada", "password": "raw-secret"}),
    );
    assert_eq!(
        serde_json::to_value(Redactor::standard().redact_view(&login)).expect("redacted view"),
        serde_json::json!({"user": "ada", "password": "<redacted>"}),
    );
}

#[test]
fn test_view_serializes_with_redacted_structure() {
    let login = Login {
        user: "ada".into(),
        password: "raw-secret".into(),
    };
    let redactor = Redactor::standard();
    let view = redactor.redact_view(&login);
    let json = serde_json::to_value(&view).expect("redacted object");
    assert_eq!(json, serde_json::json!({"user": "ada", "password": "<redacted>"}));
    assert_eq!(
        redactor.to_json(&login).expect("JSON convenience"),
        serde_json::to_string(&view).expect("view JSON")
    );
    assert_eq!(serde_json::to_value(&view).expect("second execution"), json);
    assert_eq!(format!("{view}"), redactor.redact_text(&login).text().as_str());
    assert_eq!(format!("{view:?}"), format!("{view}"));
}

struct Observed(Cell<usize>);

impl Redact for Observed {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        self.0.set(self.0.get() + 1);
        writer.record("Observed", |fields| {
            fields.unmarked("calls", || self.0.get());
        });
    }
}

#[test]
fn test_view_is_lazy_and_each_render_starts_from_the_source() {
    let value = Observed(Cell::new(0));
    let view = Redactor::standard().redact_view(&value);
    assert_eq!(value.0.get(), 0);
    assert!(format!("{view}").contains('1'));
    assert!(format!("{view}").contains('2'));
}

#[test]
fn test_view_retains_policy_after_application_default_replacement() {
    let login = Login {
        user: "ada".into(),
        password: "raw-secret".into(),
    };
    let view = Redactor::standard().redact_view(&login);
    let previous = Redactor::replace_application_default(Redactor::new(RedactionPolicy::disabled()));
    let rendered = serde_json::to_value(&view);
    let _ = Redactor::replace_application_default(previous);
    assert_eq!(rendered.expect("snapshot serialization")["password"], "<redacted>");
}

#[derive(Redact)]
#[redact(serde)]
struct JsonDocument<'a> {
    #[redact(json)]
    payload: &'a serde_json::Value,
    #[redact(json)]
    optional: Option<serde_json::Value>,
}

#[test]
fn test_derive_parsed_json_keeps_structure_and_source() {
    let source = serde_json::json!({"password":"raw-secret","public":[1,2]});
    let value = JsonDocument {
        payload: &source,
        optional: None,
    };
    let redactor = Redactor::standard();
    assert!(!redactor.redact_text(&value).text().as_str().contains("raw-secret"));
    let json = serde_json::to_value(redactor.redact_view(&value)).expect("parsed JSON field");
    assert_eq!(json["payload"]["password"], "<redacted>");
    assert_eq!(json["payload"]["public"], serde_json::json!([1, 2]));
    assert!(json["optional"].is_null());
    assert_eq!(source["password"], "raw-secret");
}

#[derive(Debug)]
struct RefusesSerialization;

impl serde::Serialize for RefusesSerialization {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("consumer serializer refused"))
    }
}

#[derive(Redact)]
#[redact(serde)]
struct FailedEvent {
    payload: RefusesSerialization,
}

#[test]
fn test_json_convenience_propagates_source_and_budget_errors() {
    let error = Redactor::standard()
        .to_json(&FailedEvent {
            payload: RefusesSerialization,
        })
        .expect_err("source error");
    assert!(error.to_string().contains("consumer serializer refused"));
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);
    let value = Login {
        user: "a long name".into(),
        password: "raw-secret".into(),
    };
    let error = redactor.to_json(&value).expect_err("output budget");
    assert!(error.to_string().contains("budget"));
    // A failed execution must leave no thread-local budget active.
    assert!(Redactor::standard().to_json(&value).is_ok());
}
