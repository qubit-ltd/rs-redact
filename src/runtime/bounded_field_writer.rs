// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded log-safe field rendering for one transaction fragment.

use std::fmt;

/// Streams one field through log escaping without exceeding its output limit.
pub(crate) struct BoundedFieldWriter {
    output: String,
    max_output_bytes: usize,
    overflowed: bool,
}

impl BoundedFieldWriter {
    /// Creates an empty writer bounded by `max_output_bytes`.
    pub(crate) fn new(max_output_bytes: usize) -> Self {
        Self {
            output: String::new(),
            max_output_bytes,
            overflowed: false,
        }
    }

    /// Reports whether a write exceeded the configured output limit.
    pub(crate) const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Returns the completed escaped output.
    pub(crate) fn finish(self) -> String {
        self.output
    }
}

impl fmt::Write for BoundedFieldWriter {
    /// Writes log-safe text until the configured byte limit is reached.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for character in value.chars() {
            let mut encoded = [0_u8; 12];
            let piece = crate::output::log_escape::encode_log_safe_character(character, &mut encoded)?;
            if self.output.len().saturating_add(piece.len()) > self.max_output_bytes {
                self.overflowed = true;
                return Err(fmt::Error);
            }
            self.output.push_str(piece);
        }
        Ok(())
    }
}
