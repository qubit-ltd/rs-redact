// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded display capture for structured scalar redaction.

use std::fmt;

/// Collects a complete `Display` rendering without exceeding an output budget.
///
/// The writer rejects the fragment that would overflow the remaining byte
/// allowance, so its captured text always ends on a UTF-8 boundary.
pub(super) struct BoundedDisplayWriter {
    /// Complete UTF-8 fragments accepted so far.
    output: String,
    /// Remaining byte allowance.
    remaining: usize,
}

impl BoundedDisplayWriter {
    /// Creates a writer limited to `remaining` UTF-8 bytes.
    #[must_use]
    pub(super) fn new(remaining: usize) -> Self {
        Self {
            output: String::new(),
            remaining,
        }
    }

    /// Returns the complete formatted value after successful formatting.
    #[must_use]
    pub(super) fn finish(self) -> String {
        self.output
    }
}

impl fmt::Write for BoundedDisplayWriter {
    /// Appends a complete fragment or stops formatting before exceeding the
    /// configured input allowance.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the complete fragment does not fit. No
    /// partial fragment is retained in that case.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if value.len() > self.remaining {
            return Err(fmt::Error);
        }
        self.output.push_str(value);
        self.remaining -= value.len();
        Ok(())
    }
}
