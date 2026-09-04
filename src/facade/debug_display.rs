// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Lazy `Debug`-to-`Display` adaptation for scalar redaction.

use std::fmt;

/// Presents a borrowed [`fmt::Debug`] value through [`fmt::Display`].
///
/// This adapter performs no eager allocation or formatting. Passing it to
/// [`crate::Redactor::redact_field`] or [`crate::RedactedTextComposer::field`]
/// lets an opaque high- or secret-sensitivity mask avoid observing the wrapped
/// value altogether. The wrapped `Debug` implementation runs only when the
/// selected policy needs the source representation, such as for pass-through,
/// disabled, low-, or medium-sensitivity rendering.
///
/// # Examples
///
/// ```
/// use qubit_redact::{DebugDisplay, Redactor};
///
/// let values = vec!["first", "second"];
/// let output = Redactor::strict().redact_field("selection", &DebugDisplay::new(&values));
/// assert_eq!(output.text().as_str(), "<redacted>");
/// ```
#[derive(Clone, Copy)]
pub struct DebugDisplay<'value, T: ?Sized> {
    /// Borrowed value whose debug representation is produced on demand.
    value: &'value T,
}

impl<'value, T: ?Sized> DebugDisplay<'value, T> {
    /// Wraps a borrowed value without formatting or allocating.
    #[must_use]
    #[inline(always)]
    pub const fn new(value: &'value T) -> Self {
        Self { value }
    }
}

impl<T> fmt::Display for DebugDisplay<'_, T>
where
    T: fmt::Debug + ?Sized,
{
    /// Lazily delegates formatting to the wrapped value's `Debug` output.
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.value, formatter)
    }
}
