#![cfg(feature = "json")]

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use serde_json::json;

#[test]
fn parsed_json_value_api_does_not_mutate_borrowed_value() {
    let value = json!({"password": "raw-secret", "visible": "shown"});
    let original = value.clone();
    let output = Redactor::strict().redact_json_value(&value);

    assert_eq!(value, original);
    assert!(!output.text().as_str().contains("raw-secret"));
    assert!(output.text().as_str().contains("visible"));
}

#[test]
fn disabled_policy_preserves_parsed_json_wire_text() {
    let value = json!({"password": "raw-secret"});
    let policy = RedactionPolicy::disabled();
    let output = Redactor::new(policy).redact_json_value(&value);

    assert_eq!(output.text().as_str(), r#"{"password":"raw-secret"}"#);
}
