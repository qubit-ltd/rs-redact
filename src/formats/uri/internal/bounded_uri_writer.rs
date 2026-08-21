// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Byte-bounded URI rendering.

use crate::RedactionCompletion;
use crate::RedactionReason;
use crate::runtime::OperationSink;

/// Marker appended when a URI cannot fit within the output bound.
const TRUNCATED: &str = "<truncated>";

/// Accumulates escaped URI text without exceeding the final output budget.
pub(crate) struct BoundedUriWriter {
    /// Runtime-owned bounded rendering state.
    sink: OperationSink,
}

impl BoundedUriWriter {
    /// Creates a bounded URI writer.
    #[must_use]
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            sink: OperationSink::new(max_bytes, TRUNCATED, false),
        }
    }

    /// Writes text after escaping log-unsafe characters.
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
    pub(crate) fn write_percent_encoded(&mut self, byte: u8) -> bool {
        let encoded = [b'%', hex_digit(byte >> 4), hex_digit(byte & 0x0f)];
        let piece = std::str::from_utf8(&encoded).expect("percent encoding is always valid ASCII");
        self.sink.write_atom(piece)
    }

    /// Reports whether output can no longer accept payload.
    #[must_use]
    #[inline]
    pub(crate) fn is_full(&self) -> bool {
        self.sink.is_full()
    }

    /// Finishes output and reports whether the effective bound was a domain
    /// limit or the shared session limit.
    pub(crate) fn finish_with_completion(self, _session_limited: bool) -> (String, RedactionCompletion) {
        let (text, completion, _) = self
            .sink
            .finish_with_reason(RedactionReason::OutputLimitReached)
            .into_parts();
        (text, completion)
    }
}

/// Converts one nibble to an uppercase hexadecimal digit.
const fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + value - 10,
    }
}
