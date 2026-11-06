// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URI encoding adapter for streaming mask output.

use std::fmt;

use super::BoundedUriWriter;

/// Adapts mask fragments to URI encoding while preserving bounded writes.
pub(crate) struct UriComponentWriter<'a> {
    /// URI output destination.
    rendered: &'a mut BoundedUriWriter,
}

impl UriComponentWriter<'_> {
    /// Creates a writer for one bounded URI component.
    ///
    /// # Parameters
    ///
    /// - `rendered`: Destination exclusively borrowed for the adapter's
    ///   lifetime.
    ///
    /// # Returns
    ///
    /// An adapter that URI-encodes fragments into the borrowed destination.
    #[must_use]
    #[inline]
    pub(crate) fn new(rendered: &mut BoundedUriWriter) -> UriComponentWriter<'_> {
        UriComponentWriter { rendered }
    }
}

impl fmt::Write for UriComponentWriter<'_> {
    /// URI-encodes `value` into the bounded destination.
    ///
    /// # Parameters
    ///
    /// - `value`: Fragment whose UTF-8 bytes are encoded and appended.
    ///
    /// # Returns
    ///
    /// `Ok(())` after writing the complete fragment.
    ///
    /// # Errors
    ///
    /// Returns `fmt::Error` when the destination truncates the fragment. The
    /// destination retains the truncation state.
    #[inline]
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if write_uri_component(value, self.rendered) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

/// Writes a replacement while retaining URI-safe delimiters.
///
/// # Parameters
///
/// - `value`: Replacement whose UTF-8 bytes are encoded, preserving URI-safe
///   delimiters.
/// - `rendered`: Bounded destination updated until completion or rejection.
///
/// # Returns
///
/// `true` when the entire replacement is written, or `false` when the
/// bounded destination rejects a byte and stops writing.
#[must_use]
fn write_uri_component(value: &str, rendered: &mut BoundedUriWriter) -> bool {
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.' | b'_' | b'~' | b'!' | b'$' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
            )
        {
            let mut buffer = [0_u8; 4];
            if !rendered.write_str(char::from(byte).encode_utf8(&mut buffer)) {
                return false;
            }
        } else if !rendered.write_percent_encoded(byte) {
            return false;
        }
    }
    true
}
