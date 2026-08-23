#![cfg(feature = "json")]

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use serde_json::Value;
use serde_json::json;

/// Builds a disabled policy whose JSON node budget rejects nested objects.
fn disabled_policy_with_one_json_node() -> RedactionPolicy {
    let builder = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_json_nodes(1);
        })
        .expect("the JSON node limit is valid");
    let mut policy = builder.build().expect("the policy is valid");
    let _ = policy.set_disabled(true);
    policy
}

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

#[test]
fn test_disabled_borrowed_json_value_respects_node_limit_across_rendering_entry_points() {
    struct Payload<'value>(&'value Value);

    impl Redact for Payload<'_> {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("Payload", |fields| {
                fields.json_value("payload", self.0);
            });
        }
    }

    let value = json!({"outer": {"secret": "raw-secret"}});
    let redactor = Redactor::new(disabled_policy_with_one_json_node());

    let direct = redactor.redact_json_value(&value);
    assert!(!direct.text().as_str().contains("raw-secret"));
    assert_eq!(direct.summary().completion(), RedactionCompletion::Truncated);
    assert!(direct.summary().is_redaction_disabled());

    let mut batch = redactor.batch();
    let handle = batch.redact_json_value(&value);
    let batch = batch.finish();
    let batched = batch
        .resolve(handle)
        .expect("the rejected JSON value remains resolvable");
    assert!(!batched.text().as_str().contains("raw-secret"));
    assert_eq!(batched.summary().completion(), RedactionCompletion::Truncated);
    assert!(batched.summary().is_redaction_disabled());

    let composed = redactor
        .text_composer()
        .json(|writer| {
            writer.value(&value);
        })
        .finish();
    assert!(!composed.text().as_str().contains("raw-secret"));
    assert_eq!(composed.summary().completion(), RedactionCompletion::Truncated);
    assert!(composed.summary().is_redaction_disabled());

    let field = redactor.redact(&Payload(&value));
    assert!(!field.text().as_str().contains("raw-secret"));
    assert_eq!(field.summary().completion(), RedactionCompletion::Truncated);
    assert!(field.summary().is_redaction_disabled());
}

#[test]
fn all_parsed_json_value_entry_points_borrow_and_redact_the_same_value() {
    struct Payload<'value>(&'value Value);

    impl Redact for Payload<'_> {
        fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
            writer.record("Payload", |fields| {
                fields.json_value("payload", self.0);
            });
        }
    }

    let value = json!({"password": "raw-secret", "visible": "shown"});
    let original = value.clone();
    let redactor = Redactor::strict();

    let inspection = redactor
        .inspect_json_value(&value)
        .expect("borrowed JSON inspection should be conclusive");
    assert!(inspection.contains_sensitive());

    let mut batch = redactor.batch();
    let handle = batch.redact_json_value(&value);
    let batch = batch.finish();
    let batch_text = batch
        .resolve(handle)
        .expect("borrowed JSON batch item should resolve")
        .text()
        .as_str();
    assert!(!batch_text.contains("raw-secret"));

    let writer_output = redactor
        .text_composer()
        .json(|writer| {
            writer.value(&value);
        })
        .finish();
    assert!(!writer_output.text().as_str().contains("raw-secret"));

    let field_output = redactor.redact(&Payload(&value));
    assert!(!field_output.text().as_str().contains("raw-secret"));
    assert!(field_output.text().as_str().contains(r#"payload: {"#));
    assert!(!field_output.text().as_str().contains(r#"payload: \"{"#));
    assert_eq!(value, original);
}
