// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for explicit in-place redaction adapters.

use qubit_redact::RedactMut;
use qubit_redact::RedactionPolicy;
/// Mutable value used to verify nested in-place replacement.
#[derive(Clone)]
struct MutableValue(String);

impl RedactMut for MutableValue {
    /// Replaces the value with the runtime's fixed redaction marker.
    fn redact_in_place_with(&mut self, _policy: &RedactionPolicy) {
        self.0 = "<redacted>".to_owned();
    }
}

/// Verifies an option delegates in-place redaction to its present value.
#[test]
fn test_nested_option_redacts_present_value_in_place() {
    let mut value = Some(MutableValue("raw".to_owned()));
    value.redact_in_place();
    assert_eq!(value.expect("the value remains present").0, "<redacted>");
}

#[test]
fn test_redact_mut_default_and_clone_helpers_delegate_to_explicit_mutation() {
    let policy = RedactionPolicy::default();
    let original = MutableValue("raw".to_owned());

    let explicit = original.clone().into_redacted_with(&policy);
    let default = original.clone().into_redacted();
    let cloned = original.to_redacted_with(&policy);
    let default_cloned = original.to_redacted();
    let mut in_place = original.clone();
    in_place.redact_in_place();

    assert_eq!(explicit.0, "<redacted>");
    assert_eq!(default.0, "<redacted>");
    assert_eq!(cloned.0, "<redacted>");
    assert_eq!(default_cloned.0, "<redacted>");
    assert_eq!(in_place.0, "<redacted>");
    assert_eq!(original.0, "raw");
}
