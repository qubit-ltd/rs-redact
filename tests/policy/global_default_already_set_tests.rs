//! Tests for [`GlobalDefaultAlreadySet`](qubit_redact::GlobalDefaultAlreadySet).

use qubit_redact::GlobalDefaultAlreadySet;

/// Verifies the global-default installation error has a stable message.
#[test]
fn test_global_default_already_set_display_is_descriptive() {
    assert_eq!(
        GlobalDefaultAlreadySet.to_string(),
        "the global default redaction policy is already set",
    );
}
