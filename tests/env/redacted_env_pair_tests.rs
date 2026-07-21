use qubit_redact::EnvRedactor;

/// Verifies that a redacted environment pair is displayable.
#[test]
fn test_redacted_env_pair_displays_assignment() {
    assert_eq!(
        EnvRedactor::default()
            .redact_pair("MODE", "debug")
            .to_string(),
        "MODE=debug"
    );
}
