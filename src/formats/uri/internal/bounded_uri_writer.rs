// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Byte-bounded URI rendering.

use std::str::from_utf8;

use crate::RedactionReason;
use crate::runtime::OperationSink;
use crate::runtime::RenderedOperation;

/// Marker appended when a URI cannot fit within the output bound.
const TRUNCATED: &str = "<truncated>";

/// Accumulates escaped URI text without exceeding the final output budget.
pub(crate) struct BoundedUriWriter {
    /// Runtime-owned bounded rendering state.
    sink: OperationSink,
}

impl BoundedUriWriter {
    /// Creates a bounded URI writer with an empty runtime-owned sink.
    ///
    /// # Parameters
    ///
    /// - `max_bytes`: Maximum retained output bytes, including any truncation
    ///   marker.
    ///
    /// # Returns
    ///
    /// A writer that escapes URI text within the supplied output bound.
    #[must_use]
    #[inline]
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            sink: OperationSink::new(max_bytes, TRUNCATED, false),
        }
    }

    /// Reports whether output can no longer accept payload.
    ///
    /// # Returns
    ///
    /// `true` if the sink has closed further output; `false` otherwise.
    #[must_use]
    #[inline]
    pub(crate) fn is_full(&self) -> bool {
        self.sink.is_full()
    }

    /// Writes text after escaping log-unsafe characters while preserving
    /// existing valid percent-encoded bytes as indivisible atoms.
    ///
    /// # Parameters
    ///
    /// - `value`: URI text to escape and append.
    ///
    /// # Returns
    ///
    /// `true` if all text was written; `false` if the output bound rejects an
    /// atom or a character cannot be encoded. Either failure stops writing,
    /// and an encoding failure marks the sink as truncated.
    pub(crate) fn write_str(&mut self, value: &str) -> bool {
        if self.sink.is_full() {
            return false;
        }
        let mut remaining = value;
        while !remaining.is_empty() {
            if remaining.as_bytes().first() == Some(&b'%')
                && remaining.len() >= 3
                && remaining.as_bytes()[1].is_ascii_hexdigit()
                && remaining.as_bytes()[2].is_ascii_hexdigit()
            {
                if !self.sink.write_atom(&remaining[..3]) {
                    return false;
                }
                remaining = &remaining[3..];
                continue;
            }
            let character = remaining.chars().next().expect("non-empty text has a first character");
            let mut encoded = [0_u8; 12];
            let Ok(piece) = crate::output::log_escape::encode_log_safe_character(character, &mut encoded) else {
                self.sink.mark_truncated();
                return false;
            };
            if !self.sink.write_atom(piece) {
                return false;
            }
            remaining = &remaining[character.len_utf8()..];
        }
        true
    }

    /// Writes one complete percent-encoded byte atomically.
    ///
    /// # Parameters
    ///
    /// - `byte`: Byte to represent using uppercase hexadecimal digits.
    ///
    /// # Returns
    ///
    /// `true` if the complete three-byte escape was retained; `false` if the
    /// output bound rejected it and closed further output.
    pub(crate) fn write_percent_encoded(&mut self, byte: u8) -> bool {
        let encoded = [b'%', hex_digit(byte >> 4), hex_digit(byte & 0x0f)];
        let piece = from_utf8(&encoded).expect("percent encoding is always valid ASCII");
        self.sink.write_atom(piece)
    }

    /// Finalizes URI atoms without discarding output exhaustion provenance.
    ///
    /// # Returns
    ///
    /// The owned rendered text and completion provenance, including an
    /// output-limit reason when the sink rejected output.
    #[inline]
    pub(crate) fn finish(self) -> RenderedOperation {
        self.sink.finish_with_reason(RedactionReason::OutputLimitReached)
    }
}

/// Converts one nibble to an uppercase hexadecimal digit.
///
/// # Parameters
///
/// - `value`: Nibble in the range `0..=15` supplied by byte decomposition.
///
/// # Returns
///
/// The ASCII byte of the corresponding uppercase hexadecimal digit.
#[must_use]
#[inline]
const fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + value - 10,
    }
}
