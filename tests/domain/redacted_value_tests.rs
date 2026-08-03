// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedValue`](qubit_redact::RedactedValue).

use std::fmt::{
    self,
    Write,
};

use qubit_redact::{
    MaskPolicy,
    MaskingPolicy,
    RedactValue,
    RedactedValue,
    Sensitivity,
};

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

/// Verifies the absent optional representation keeps both output protocols.
#[test]
fn test_redacted_value_none_preserves_optional_shape() {
    let value = RedactedValue::None;

    assert_eq!(format!("{value:?}"), "None");
    assert_eq!(value.to_string(), "None");
    #[cfg(feature = "serde")]
    assert_eq!(
        serde_json::to_value(&value).expect("none should serialize"),
        serde_json::Value::Null,
    );
}

/// Writer that rejects a configured write operation.
struct FailingWriter {
    /// One-based write operation that should fail.
    fail_on_call: usize,
    /// Number of write operations attempted so far.
    calls: usize,
}

impl FailingWriter {
    /// Creates a writer that fails on the configured write call.
    ///
    /// # Parameters
    ///
    /// * `fail_on_call` - One-based call index to reject.
    ///
    /// # Returns
    ///
    /// A writer that can exercise formatter error propagation.
    const fn new(fail_on_call: usize) -> Self {
        Self {
            fail_on_call,
            calls: 0,
        }
    }
}

impl Write for FailingWriter {
    /// Rejects the configured write call and accepts all others.
    ///
    /// # Parameters
    ///
    /// * `value` - Text the formatter attempts to write.
    ///
    /// # Returns
    ///
    /// [`fmt::Error`] on the configured failing call; otherwise success.
    fn write_str(&mut self, _value: &str) -> fmt::Result {
        self.calls += 1;
        if self.calls == self.fail_on_call {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}

/// Verifies optional display propagates formatter failures before content.
#[test]
fn test_redacted_value_some_display_propagates_prefix_write_error() {
    let masking = MaskingPolicy::default();
    let value = Some("raw").redact_value(Sensitivity::Secret, &masking);
    let mut writer = FailingWriter::new(1);

    let result = write!(&mut writer, "{value}");

    assert!(result.is_err());
}

/// Verifies optional display propagates formatter failures from content.
#[test]
fn test_redacted_value_some_display_propagates_content_write_error() {
    let masking = MaskingPolicy::default();
    let value = Some("raw").redact_value(Sensitivity::Secret, &masking);
    let mut writer = FailingWriter::new(2);

    let result = write!(&mut writer, "{value}");

    assert!(result.is_err());
}
