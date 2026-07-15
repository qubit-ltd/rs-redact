// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Debug wrapper that never formats the wrapped value.

use std::fmt::{
    self,
    Debug,
    Formatter,
};

/// Formats any borrowed value as a fixed redaction marker.
///
/// This wrapper deliberately does not require or invoke the wrapped value's
/// [`Debug`] implementation.
pub struct RedactedDebug<'a, T: ?Sized> {
    /// Borrowed value retained only to bind the wrapper's lifetime.
    value: &'a T,
}

impl<'a, T: ?Sized> RedactedDebug<'a, T> {
    /// Creates a debug wrapper that always renders a redaction marker.
    ///
    /// # Parameters
    ///
    /// * `value` - Value whose debug representation must remain hidden.
    ///
    /// # Returns
    ///
    /// A fixed-marker debug wrapper borrowing `value`.
    #[inline(always)]
    pub const fn new(value: &'a T) -> Self {
        Self { value }
    }
}

impl<T: ?Sized> Debug for RedactedDebug<'_, T> {
    /// Writes a fixed marker without formatting the wrapped value.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let _ = self.value;
        formatter.write_str("<redacted>")
    }
}

/// Wraps a borrowed value in a fixed-marker debug representation.
///
/// # Parameters
///
/// * `value` - Value whose debug representation must remain hidden.
///
/// # Returns
///
/// A wrapper that formats as `<redacted>` without invoking `value`'s
/// [`Debug`] implementation.
#[inline(always)]
pub const fn redacted_debug<T: ?Sized>(value: &T) -> RedactedDebug<'_, T> {
    RedactedDebug::new(value)
}
