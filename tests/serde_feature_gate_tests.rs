use qubit_redact::Redactor;

/// Verifies that core redaction remains available through feature selection.
#[test]
fn test_serde_feature_gate_keeps_core_redaction_available() {
    assert_eq!(
        Redactor::default().redact("password", "raw").as_str(),
        "<redacted>",
    );
}
