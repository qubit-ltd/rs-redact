// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactValueMut`](qubit_redact::RedactValueMut).

use qubit_redact::{MaskingPolicy, RedactValueMut, Sensitivity};

/// Verifies in-place scalar redaction replaces an owned secret value.
#[test]
fn test_redact_value_mut_replaces_owned_string() {
    let mut value = String::from("raw");
    value.redact_value_in_place(Sensitivity::Secret, &MaskingPolicy::default());

    assert_eq!(value, "<redacted>");
}
