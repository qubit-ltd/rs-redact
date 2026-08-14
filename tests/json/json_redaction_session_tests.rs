use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use serde_json::json;

#[test]
fn output_exhaustion_skips_json_input() {
    let budget = InputOutputLimit::new(8, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("marker-sized output budget is valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("policy is valid");
    let redactor = Redactor::new(policy);
    let mut session = redactor.session();
    let _ = session.json().redact_text("{\"token\":\"secret\"}");
    let input_before = session.remaining_input_bytes();
    let result = session.json().redact_value(&json!({
        "token": "must-not-be-read",
    }));
    assert_eq!(result.as_str(), "");
    assert_eq!(session.remaining_input_bytes(), input_before);
}
