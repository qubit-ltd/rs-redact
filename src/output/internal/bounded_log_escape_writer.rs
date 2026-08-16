// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded streaming log-control escaping.

use std::fmt;
use std::fmt::Write;

use crate::LogOutputLimit;
use crate::output::log_escape::encode_log_safe_character;
use crate::output::log_output_limit::TRUNCATION_MARKER;

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
    #[must_use]
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
    #[must_use]
    #[inline(always)]
    pub(crate) const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns the number of bytes currently retained by the writer.
    #[inline(always)]
    pub(crate) fn len(&self) -> usize {
        self.output.len()
    }

    /// Appends one complete UTF-8 character or escape sequence.
    ///
    /// # Parameters
    ///
    /// * `piece` - Atomic log-safe text corresponding to one input character.
    ///
    /// # Returns
    ///
    /// `true` when the complete piece was appended, or `false` after
    /// truncation.
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

/// Splits one complete pre-generated debug escape from `value`.
///
/// # Parameters
///
/// * `value` - Remaining already log-safe text to inspect.
///
/// # Returns
///
/// `Some((escape, rest))` when `value` starts with one complete Rust debug
/// escape, or `None` when its first character must be escaped normally.
fn split_debug_escape(value: &str) -> Option<(&str, &str)> {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'\\') {
        return None;
    }
    match bytes.get(1).copied()? {
        b'\\' | b'"' | b'n' | b'r' | b't' | b'0' => {
            Some((&value[..2], &value[2..]))
        }
        b'x' if bytes.len() >= 4
            && bytes[2].is_ascii_hexdigit()
            && bytes[3].is_ascii_hexdigit() =>
        {
            Some((&value[..4], &value[4..]))
        }
        b'u' if bytes.get(2) == Some(&b'{') => {
            let closing = bytes[3..]
                .iter()
                .position(|byte| *byte == b'}')
                .map(|index| index + 3)?;
            if closing == 3
                || !bytes[3..closing].iter().all(u8::is_ascii_hexdigit)
            {
                return None;
            }
            Some((&value[..=closing], &value[closing + 1..]))
        }
        _ => None,
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
        let mut remaining = value;
        while let Some(character) = remaining.chars().next() {
            if let Some((escape, rest)) = split_debug_escape(remaining) {
                if !self.write_piece(escape) {
                    return Err(fmt::Error);
                }
                remaining = rest;
                continue;
            }
            let mut buffer = [0_u8; 12];
            let piece = encode_log_safe_character(character, &mut buffer)?;
            if !self.write_piece(piece) {
                return Err(fmt::Error);
            }
            remaining = &remaining[character.len_utf8()..];
        }
        Ok(())
    }
}
