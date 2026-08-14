use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::http::BodyCapture;
use qubit_redact::http::HttpRedactor;

#[test]
fn output_exhaustion_skips_body_input() {
    let budget = InputOutputLimit::new(8, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("marker-sized output budget is valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("policy is valid");
    let redactor = HttpRedactor::new(policy);
    let mut session = redactor.session();
    let _ = session
        .http()
        .redact_url_str("https://user:password@example.com/path?token=secret");
    let input_before = session.remaining_input_bytes();
    let result = session.http().redact_body_with_content_type_text(
        BodyCapture::complete(br#"{"token":"must-not-be-read"}"#),
        Some("application/json"),
    );
    assert_eq!(result.log_safe_text().as_str(), "");
    assert_eq!(session.remaining_input_bytes(), input_before);
}
