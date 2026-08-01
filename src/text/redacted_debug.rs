// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! A debug wrapper that emits a fixed redaction marker.

use std::fmt::{
    Debug,
    Formatter,
    Result,
};

/// A borrowed value whose debug representation is always `<redacted>`.
///
/// This wrapper does not require or invoke `T`'s [`Debug`] implementation. It
/// retains the borrow so the wrapper cannot outlive the value it protects.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use qubit_redact::redacted_debug;
///
/// let secret = String::from("secret");
/// redacted_debug(&secret);
/// ```
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the protected borrowed value.
/// * `T` - Protected value type, which need not implement [`Debug`].
#[must_use = "render the redacted debug marker instead of discarding it"]
pub struct RedactedDebug<'a, T: ?Sized> {
    /// The protected value, retained only to preserve its borrow and traits.
    _value: &'a T,
}

impl<T: ?Sized> Debug for RedactedDebug<'_, T> {
    /// Writes the fixed redaction marker without formatting the wrapped value.
    ///
    /// # Parameters
    ///
    /// - `formatter`: Destination formatter.
    ///
    /// # Returns
    ///
    /// The result of writing the marker to `formatter`.
    ///
    /// # Errors
    ///
    /// Returns [`std::fmt::Error`] when the formatter rejects the write.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result {
        formatter.write_str("<redacted>")
    }
}

/// Wraps a value so debug formatting emits only `<redacted>`.
///
/// The returned wrapper never invokes the value's [`Debug`] implementation.
///
/// # Type Parameters
///
/// * `T` - Protected value type, which need not implement [`Debug`].
///
/// # Parameters
///
/// - `value`: The value whose debug representation must be hidden.
///
/// # Returns
///
/// A wrapper borrowing `value` and rendering the fixed redaction marker.
#[inline(always)]
pub const fn redacted_debug<T: ?Sized>(value: &T) -> RedactedDebug<'_, T> {
    RedactedDebug { _value: value }
}
