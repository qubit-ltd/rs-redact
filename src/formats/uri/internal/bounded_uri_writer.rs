// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Byte-bounded URI rendering.

use crate::output::log_escape::encode_log_safe_character;
use crate::RedactionCompletion;

/// Marker appended when a URI cannot fit within the output bound.
const TRUNCATED: &str = "<truncated>";

/// Accumulates escaped URI text without exceeding the final output budget.
pub(crate) struct BoundedUriWriter {
    /// Escaped payload accumulated so far.
    output: String,
    /// Last complete piece boundary that leaves room for the marker.
    marker_boundary: usize,
    /// Maximum final output bytes including the marker.
    max_bytes: usize,
    /// Whether a piece failed to fit and output must be marked truncated.
    truncated: bool,
}

impl BoundedUriWriter {
    /// Creates a bounded URI writer.
    #[must_use]
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            output: String::new(),
            marker_boundary: 0,
            max_bytes,
            truncated: false,
        }
    }

    /// Writes text after escaping log-unsafe characters.
    pub(crate) fn write_str(&mut self, value: &str) -> bool {
        if self.truncated {
            return false;
        }
        let mut remaining = value;
        while !remaining.is_empty() {
            if remaining.as_bytes().first() == Some(&b'%')
                && remaining.len() >= 3
                && remaining.as_bytes()[1].is_ascii_hexdigit()
                && remaining.as_bytes()[2].is_ascii_hexdigit()
            {
                if !self.append_piece(&remaining[..3]) {
                    return false;
                }
                remaining = &remaining[3..];
                continue;
            }
            let character = remaining.chars().next().expect("non-empty text has a first character");
            let mut encoded = [0_u8; 12];
            let Ok(piece) = encode_log_safe_character(character, &mut encoded) else {
                self.truncate();
                return false;
            };
            if !self.append_piece(piece) {
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
        self.append_piece(piece)
    }

    /// Reports whether output can no longer accept payload.
    #[must_use]
    #[inline]
    pub(crate) const fn is_full(&self) -> bool {
        self.truncated
    }

    /// Finishes output and reports whether the effective bound was a domain
    /// limit or the shared session limit.
    pub(crate) fn finish_with_completion(mut self, session_limited: bool) -> (String, RedactionCompletion) {
        if self.truncated {
            if self.max_bytes < TRUNCATED.len() {
                return (
                    String::new(),
                    if session_limited {
                        RedactionCompletion::Truncated
                    } else {
                        RedactionCompletion::Truncated
                    },
                );
            }
            self.output.truncate(self.marker_boundary);
            self.output.push_str(TRUNCATED);
        }
        (
            self.output,
            if self.truncated {
                if session_limited {
                    RedactionCompletion::Truncated
                } else {
                    RedactionCompletion::Truncated
                }
            } else {
                RedactionCompletion::Complete
            },
        )
    }

    /// Appends one complete escaped piece when it fits.
    fn append_piece(&mut self, piece: &str) -> bool {
        if self.truncated {
            return false;
        }
        if self.output.len().saturating_add(piece.len()) > self.max_bytes {
            self.truncate();
            return false;
        }
        self.output.push_str(piece);
        let payload_limit = self.max_bytes.saturating_sub(TRUNCATED.len());
        if self.output.len() <= payload_limit {
            self.marker_boundary = self.output.len();
        }
        true
    }

    /// Marks output truncated after retaining the last marker-safe boundary.
    fn truncate(&mut self) {
        self.output.truncate(self.marker_boundary);
        self.truncated = true;
    }
}

/// Converts one nibble to an uppercase hexadecimal digit.
const fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + value - 10,
    }
}
