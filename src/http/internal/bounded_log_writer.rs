// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded construction of log-safe HTTP body text.

use std::fmt;

use super::markers;
use crate::text::log_escape::encode_log_safe_character;

/// Accumulates escaped log text without exceeding a final byte budget.
pub(in crate::http) struct BoundedLogWriter {
    /// Escaped payload accumulated so far.
    output: String,
    /// Last complete escaped-piece boundary that leaves room for the marker.
    marker_boundary: usize,
    /// Maximum final length including the truncation marker.
    max_bytes: usize,
    /// Whether the final result requires a truncation marker.
    truncated: bool,
    /// Whether an output piece failed to fit in the final byte budget.
    output_truncated: bool,
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
            output: String::new(),
            marker_boundary: 0,
            max_bytes,
            truncated: source_truncated,
            output_truncated: false,
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
        let value = if self.truncated {
            value.strip_suffix(markers::TRUNCATED).unwrap_or(value)
        } else {
            value
        };
        for character in value.chars() {
            let mut encoded = [0_u8; 12];
            let piece = encode_log_safe_character(character, &mut encoded)?;
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
    #[must_use]
    #[inline(always)]
    pub(in crate::http) fn is_full(&self) -> bool {
        self.output_truncated
            || (self.truncated && self.output.len() >= self.payload_limit())
    }

    /// Returns bytes still available before the current payload limit.
    ///
    /// # Returns
    ///
    /// Remaining payload bytes before any required truncation marker.
    #[inline(always)]
    pub(in crate::http) fn remaining_bytes(&self) -> usize {
        self.payload_limit().saturating_sub(self.output.len())
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
            let marker_payload_limit =
                self.max_bytes - markers::TRUNCATED.len();
            if self.output.len() <= marker_payload_limit {
                self.marker_boundary = self.output.len();
            }
            return true;
        }
        self.truncated = true;
        self.output_truncated = true;
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

    /// Truncates accumulated text to a complete marker-reserved piece.
    fn truncate_to_payload_limit(&mut self) {
        self.output.truncate(self.marker_boundary);
    }
}
