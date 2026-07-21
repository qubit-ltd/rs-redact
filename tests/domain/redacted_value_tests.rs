//! Tests for [`RedactedValue`](qubit_redact::RedactedValue).

use qubit_redact::{
    MaskingPolicy,
    RedactValue,
    Sensitivity,
};

/// Verifies redacted scalar values have a log-safe display representation.
#[test]
fn test_redacted_value_displays_masked_secret() {
    let value =
        "raw".redact_value(Sensitivity::Secret, &MaskingPolicy::default());

    assert_eq!(value.to_string(), "<redacted>");
}
