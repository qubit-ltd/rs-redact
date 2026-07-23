// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded construction of log-safe HTTP body text.

use std::fmt;

use crate::text::log_escape::is_log_unsafe_character;

use super::markers;

/// Accumulates escaped log text without exceeding a final byte budget.
pub(in crate::http) struct BoundedLogWriter {
    /// Escaped payload accumulated so far.
    output: String,
    /// Maximum final length including the truncation marker.
    max_bytes: usize,
    /// Whether the final result requires a truncation marker.
    truncated: bool,
}

impl BoundedLogWriter {
    /// Creates a bounded writer.
    ///
    /// # Parameters
    ///
    /// * `max_bytes` - Maximum final output bytes, including the marker.
    /// * `source_truncated` - Whether source bytes were already omitted.
    ///
    /// # Returns
    ///
    /// An empty writer that reserves marker space when source is truncated.
    pub(in crate::http) fn new(
        max_bytes: usize,
        source_truncated: bool,
    ) -> Self {
        Self {
            output: String::with_capacity(max_bytes),
            max_bytes,
            truncated: source_truncated,
        }
    }

    /// Writes text while escaping log-unsafe characters and enforcing budget.
    ///
    /// # Parameters
    ///
    /// * `value` - Redacted text to append.
    ///
    /// # Returns
    ///
    /// `Ok(())` after appending the longest escaped prefix that fits.
    ///
    /// # Errors
    ///
    /// This implementation currently cannot return a formatting error.
    pub(in crate::http) fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.is_full() {
            return Ok(());
        }
        for character in value.chars() {
            let mut encoded = [0_u8; 12];
            let piece = if is_log_unsafe_character(character) {
                let escaped = character.escape_debug().to_string();
                if !self.append_piece(&escaped) {
                    break;
                }
                continue;
            } else {
                character.encode_utf8(&mut encoded)
            };
            if !self.append_piece(piece) {
                break;
            }
        }
        Ok(())
    }

    /// Reports whether no more payload can affect the final result.
    ///
    /// # Returns
    ///
    /// `true` after output truncation or when a source-truncated payload has
    /// filled all bytes preceding the marker.
    #[inline(always)]
    pub(in crate::http) fn is_full(&self) -> bool {
        let limit = self.payload_limit();
        self.output.len() >= limit
    }

    /// Finishes the bounded rendering.
    ///
    /// # Returns
    ///
    /// Final log-safe text and whether any source or output was truncated.
    pub(in crate::http) fn finish(mut self) -> (String, bool) {
        if self.truncated {
            self.truncate_to_payload_limit();
            self.output.push_str(markers::TRUNCATED);
        }
        (self.output, self.truncated)
    }

    /// Appends one already-escaped character representation.
    ///
    /// # Parameters
    ///
    /// * `piece` - One complete UTF-8 character or escape sequence.
    ///
    /// # Returns
    ///
    /// `true` when appended, or `false` after marking output truncated.
    fn append_piece(&mut self, piece: &str) -> bool {
        let limit = self.payload_limit();
        if self.output.len().saturating_add(piece.len()) <= limit {
            self.output.push_str(piece);
            return true;
        }
        self.truncated = true;
        self.truncate_to_payload_limit();
        false
    }

    /// Returns the current payload limit before any marker.
    ///
    /// # Returns
    ///
    /// The full limit for complete output, otherwise marker-reserved bytes.
    #[inline(always)]
    fn payload_limit(&self) -> usize {
        if self.truncated {
            self.max_bytes - markers::TRUNCATED.len()
        } else {
            self.max_bytes
        }
    }

    /// Truncates accumulated text to a valid UTF-8 marker-reserved boundary.
    fn truncate_to_payload_limit(&mut self) {
        let mut end = self.output.len().min(self.payload_limit());
        while !self.output.is_char_boundary(end) {
            end -= 1;
        }
        self.output.truncate(end);
    }
}
