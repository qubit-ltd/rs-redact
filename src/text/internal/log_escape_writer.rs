// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Streaming log-control escaping.

use std::fmt;
use std::fmt::Write;

use crate::text::log_escape::is_log_unsafe_character;

/// Escapes log-unsafe characters while streaming into another formatter.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed output formatter.
/// * `W` - Formatting destination receiving escaped text.
pub(crate) struct LogEscapeWriter<'a, W: Write + ?Sized> {
    /// Destination receiving only log-safe text.
    output: &'a mut W,
}

impl<'a, W: Write + ?Sized> LogEscapeWriter<'a, W> {
    /// Creates a streaming escaping adapter.
    ///
    /// # Parameters
    ///
    /// * `output` - Destination that receives escaped text.
    ///
    /// # Returns
    ///
    /// A writer borrowing `output`.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn new(output: &'a mut W) -> Self {
        Self { output }
    }
}

impl<W: Write + ?Sized> Write for LogEscapeWriter<'_, W> {
    /// Writes text while escaping controls and Unicode line-ordering markers.
    ///
    /// # Parameters
    ///
    /// * `value` - Redacted text to stream into the destination.
    ///
    /// # Returns
    ///
    /// `Ok(())` after the complete escaped value is written.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination rejects any output.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for character in value.chars() {
            if is_log_unsafe_character(character) {
                for escaped in character.escape_debug() {
                    self.output.write_char(escaped)?;
                }
            } else {
                self.output.write_char(character)?;
            }
        }
        Ok(())
    }
}
