// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded streaming log-control escaping.

use std::fmt::{
    self,
    Write,
};

use crate::{
    LogOutputLimit,
    text::{
        log_escape::encode_log_safe_character,
        log_output_limit::TRUNCATION_MARKER,
    },
};

/// Escapes log-unsafe characters into a byte-bounded owned string.
pub(crate) struct BoundedLogEscapeWriter {
    /// Output retained within the configured byte budget.
    output: String,
    /// Maximum output bytes including the truncation marker.
    max_bytes: usize,
    /// Last complete piece boundary that leaves room for the marker.
    marker_boundary: usize,
    /// Whether output has already been finalized with the marker.
    truncated: bool,
}

impl BoundedLogEscapeWriter {
    /// Creates a bounded escaping destination.
    ///
    /// # Parameters
    ///
    /// * `limit` - Validated maximum output byte count.
    ///
    /// # Returns
    ///
    /// An empty bounded writer.
    #[inline]
    pub(crate) fn new(limit: LogOutputLimit) -> Self {
        Self {
            output: String::new(),
            max_bytes: limit.max_bytes(),
            marker_boundary: 0,
            truncated: false,
        }
    }

    /// Returns the completed bounded log-safe output.
    ///
    /// # Returns
    ///
    /// The escaped output, with a marker when truncation occurred.
    #[inline(always)]
    pub(crate) fn finish(self) -> String {
        self.output
    }

    /// Reports whether an input piece exceeded the output budget.
    ///
    /// # Returns
    ///
    /// True when the writer finalized its truncation marker.
    #[inline(always)]
    pub(crate) const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Appends one complete UTF-8 character or escape sequence.
    ///
    /// # Parameters
    ///
    /// * `piece` - Atomic log-safe text corresponding to one input character.
    fn write_piece(&mut self, piece: &str) -> bool {
        if self.truncated {
            return false;
        }
        if piece.len() <= self.max_bytes - self.output.len() {
            self.output.push_str(piece);
            let payload_limit = self.max_bytes - TRUNCATION_MARKER.len();
            if self.output.len() <= payload_limit {
                self.marker_boundary = self.output.len();
            }
            return true;
        }
        self.output.truncate(self.marker_boundary);
        self.output.push_str(TRUNCATION_MARKER);
        self.truncated = true;
        false
    }
}

impl Write for BoundedLogEscapeWriter {
    /// Writes escaped text without exceeding the configured byte budget.
    ///
    /// # Parameters
    ///
    /// * `value` - Redacted text to escape and append.
    ///
    /// # Returns
    ///
    /// Ok when the complete input fits in the budget.
    ///
    /// # Errors
    ///
    /// Returns an error after finalizing truncation so cooperative formatters
    /// stop producing additional pieces.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for character in value.chars() {
            let mut buffer = [0_u8; 12];
            let piece = encode_log_safe_character(character, &mut buffer)?;
            if !self.write_piece(piece) {
                return Err(fmt::Error);
            }
        }
        Ok(())
    }
}
