// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed, quote-aware traversal of header parameter segments.

use super::trim_ows;

/// Borrows semicolon-delimited segments while validating quote balance.
pub(super) struct SegmentCursor<'a> {
    /// Original header text borrowed for the entire cursor lifetime.
    value: &'a str,
    /// Byte offset where the next segment begins.
    start: usize,
    /// Byte offset of the next byte to scan in the original text.
    position: usize,
    /// Whether scanning is currently inside a quoted string.
    quoted: bool,
    /// Whether the preceding quoted backslash escapes the next byte.
    escaped: bool,
    /// Whether the final segment has already been consumed.
    finished: bool,
}

impl<'a> SegmentCursor<'a> {
    /// Creates a cursor over the complete header value.
    ///
    /// # Parameters
    ///
    /// * `value` - Header text whose segments will be borrowed.
    ///
    /// # Returns
    ///
    /// A cursor positioned before the leading segment.
    #[must_use]
    #[inline]
    pub(super) fn new(value: &'a str) -> Self {
        Self {
            value,
            start: 0,
            position: 0,
            quoted: false,
            escaped: false,
            finished: false,
        }
    }

    /// Returns the next borrowed segment or a quoting error.
    ///
    /// # Returns
    ///
    /// `Ok(Some(segment))` borrows the next OWS-trimmed segment; `Ok(None)`
    /// indicates that the final segment has already been consumed.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` for an unterminated quote or trailing quoted escape.
    pub(super) fn next_segment(&mut self) -> Result<Option<&'a str>, ()> {
        if self.finished {
            return Ok(None);
        }
        let bytes = self.value.as_bytes();
        while self.position < bytes.len() {
            let index = self.position;
            let byte = bytes[index];
            self.position += 1;
            if self.escaped {
                self.escaped = false;
            } else if self.quoted && byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.quoted = !self.quoted;
            } else if byte == b';' && !self.quoted {
                let start = self.start;
                self.start = self.position;
                return Ok(Some(trim_ows(&self.value[start..index])));
            }
        }
        self.finished = true;
        if self.quoted || self.escaped {
            return Err(());
        }
        Ok(Some(trim_ows(&self.value[self.start..])))
    }
}
