// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for serde redaction of domain objects.

#[cfg(feature = "serde")]
use qubit_redact::domain::RedactedValue;

/// Asserts at compile time that a type implements [`serde::Serialize`].
#[cfg(feature = "serde")]
fn assert_serialize<T: serde::Serialize>() {}

/// Verifies redacted scalar values implement serde serialization.
#[cfg(feature = "serde")]
#[test]
fn test_redact_serialize_redacted_value_implements_serialize() {
    assert_serialize::<RedactedValue<'static>>();
}
