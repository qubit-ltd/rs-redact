// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedValue`](qubit_redact::RedactedValue).

use qubit_redact::{MaskPolicy, MaskingPolicy, RedactValue, RedactedValue, Sensitivity};

/// Verifies redacted scalar values have a log-safe display representation.
#[test]
fn test_redacted_value_displays_masked_secret() {
    let masking = MaskingPolicy::default();
    let value = "raw".redact_value(Sensitivity::Secret, &masking);

    assert_eq!(value.to_string(), "<redacted>");
}

/// Verifies opaque redaction uses the complete configured replacement.
#[test]
fn test_redacted_value_opaque_uses_configured_complete_replacement() {
    let masking = MaskingPolicy::default().with_policy(
        Sensitivity::Low,
        MaskPolicy::preserve_edges(1, 1, "OPAQUE", 0),
    );

    let value = RedactedValue::opaque(Sensitivity::Low, &masking);

    assert_eq!(format!("{value:?}"), "\"OPAQUE\"");
    assert_eq!(value.to_string(), "OPAQUE");
}
