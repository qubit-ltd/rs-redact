use qubit_redact::EnvRedactor;

/// Verifies that environment redaction masks a password value.
#[test]
fn test_env_redactor_masks_password_value() {
    assert_eq!(
        EnvRedactor::default()
            .redact_pair("PASSWORD", "raw")
            .to_string(),
        "PASSWORD=<redacted>"
    );
}
