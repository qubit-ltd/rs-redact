// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded display capture for structured scalar redaction.

use std::fmt;

/// Collects a complete `Display` rendering without exceeding its admitted byte
/// allowance.
///
/// The writer rejects the fragment that would overflow the remaining byte
/// allowance, so its captured text always ends on a UTF-8 boundary.
pub(super) struct BoundedDisplayWriter {
    /// Complete UTF-8 fragments accepted so far.
    output: String,
    /// Remaining byte allowance.
    remaining: usize,
    /// First rejected write permanently prevents successful finalization.
    rejected: bool,
}

impl BoundedDisplayWriter {
    /// Creates a writer limited to `remaining` UTF-8 bytes.
    ///
    /// # Parameters
    ///
    /// - `remaining`: Maximum accepted raw UTF-8 bytes.
    ///
    /// # Returns
    ///
    /// An empty capture with no rejected write.
    #[must_use]
    #[inline(always)]
    pub(super) fn new(remaining: usize) -> Self {
        Self {
            output: String::new(),
            remaining,
            rejected: false,
        }
    }

    /// Returns `Some` with all accepted fragments if no write was rejected.
    ///
    /// Returns `None` after any rejected write. The caller must separately
    /// check whether the formatter itself returned an error.
    ///
    /// # Returns
    ///
    /// `Some(text)` if every submitted fragment fit; `None` after any
    /// rejection. The caller must also check the formatter result before
    /// using the text.
    #[must_use]
    #[inline(always)]
    pub(super) fn finish(self) -> Option<String> {
        (!self.rejected).then_some(self.output)
    }
}

impl fmt::Write for BoundedDisplayWriter {
    /// Appends a complete fragment or stops formatting before exceeding the
    /// configured input allowance.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when this or an earlier fragment does not fit. No
    /// partial fragment is retained in that case.
    ///
    /// # Parameters
    ///
    /// - `value`: Atomic UTF-8 fragment offered by the formatter.
    ///
    /// # Returns
    ///
    /// Success after accepting the complete fragment within the remaining byte
    /// allowance.
    #[inline]
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.rejected || value.len() > self.remaining {
            self.rejected = true;
            return Err(fmt::Error);
        }
        self.output.push_str(value);
        self.remaining -= value.len();
        Ok(())
    }
}
