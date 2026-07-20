// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedDebug`](qubit_redact::RedactedDebug).

use qubit_redact::{
    RedactedDebug,
    redacted_debug,
};

use super::internal::{
    NoDebug,
    PanicDebug,
};

/// Wraps a borrowed value while preserving its explicit lifetime.
///
/// # Parameters
///
/// - `value`: The value whose debug representation must remain hidden.
///
/// # Returns
///
/// A redacted debug wrapper carrying the same named lifetime as `value`.
#[inline(always)]
fn wrap_with_lifetime<'a, T: ?Sized>(value: &'a T) -> RedactedDebug<'a, T> {
    redacted_debug(value)
}

/// Verifies all debug formatting emits the fixed marker without inspecting the
/// wrapped value.
#[test]
fn test_redacted_debug_emits_marker_without_calling_inner_debug() {
    let redacted = redacted_debug(&PanicDebug);

    assert_eq!(format!("{redacted:?}"), "<redacted>");
    assert_eq!(format!("{redacted:#?}"), "<redacted>");
}

/// Verifies the wrapper preserves the input lifetime and accepts unsized
/// values without requiring their `Debug` implementation.
#[test]
fn test_redacted_debug_preserves_lifetime_and_accepts_unsized_values() {
    let secret = String::from("secret");
    let redacted: RedactedDebug<'_, str> = wrap_with_lifetime(secret.as_str());
    let values = [NoDebug];
    let redacted_slice: RedactedDebug<'_, [NoDebug]> =
        wrap_with_lifetime(&values[..]);

    assert_eq!(format!("{redacted:?}"), "<redacted>");
    assert_eq!(format!("{redacted_slice:?}"), "<redacted>");
}
