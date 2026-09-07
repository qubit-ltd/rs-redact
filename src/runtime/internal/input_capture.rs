// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Atomic UTF-8 input capture with a latched admission failure.

use std::fmt;

use super::scalar_failure::ScalarFailure;

/// Retains only admitted chunks while measuring every submitted byte.
pub(in crate::runtime) struct InputCapture {
    /// Admitted raw text, discarded by the caller on any formatting failure.
    text: String,
    /// Maximum admitted UTF-8 bytes.
    maximum: usize,
    /// Submitted bytes, including rejected chunks.
    presented: usize,
    /// A rejected write permanently closes this capture.
    overflowed: bool,
}

impl InputCapture {
    /// Starts a capture with the transaction's remaining input allowance.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Remaining admitted raw UTF-8 byte allowance.
    ///
    /// # Returns
    ///
    /// An empty capture with no rejection recorded.
    #[must_use]
    #[inline(always)]
    pub(in crate::runtime) fn new(maximum: usize) -> Self {
        Self {
            text: String::new(),
            maximum,
            presented: 0,
            overflowed: false,
        }
    }

    /// Reports submitted and admitted bytes even when the text cannot be used.
    ///
    /// # Returns
    ///
    /// Submitted bytes followed by accepted bytes. Rejected chunks count only
    /// toward the first component; accepted text still counts if formatting
    /// fails.
    #[must_use]
    #[inline(always)]
    pub(in crate::runtime) fn usage(&self) -> (usize, usize) {
        (self.presented, self.text.len())
    }

    /// Prioritizes the capture's rejection over the propagated formatting
    /// error.
    ///
    /// # Errors
    ///
    /// Returns `InputLimit` after any rejected chunk, including when the
    /// formatter ignores its error; otherwise propagates a formatter failure.
    ///
    /// # Parameters
    ///
    /// - `result`: Outcome returned by the value's formatter.
    ///
    /// # Returns
    ///
    /// The complete accepted text when neither capture nor formatter failed.
    pub(in crate::runtime) fn finish(self, result: fmt::Result) -> Result<String, ScalarFailure> {
        if self.overflowed {
            Err(ScalarFailure::InputLimit)
        } else if result.is_err() {
            Err(ScalarFailure::FormatterFailure)
        } else {
            Ok(self.text)
        }
    }
}

impl fmt::Write for InputCapture {
    /// Rejects an entire chunk atomically and never reopens after rejection.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] if this chunk exceeds the allowance or a previous
    /// chunk already closed the capture.
    ///
    /// # Parameters
    ///
    /// - `value`: One atomic UTF-8 chunk submitted by the formatter.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.presented = self.presented.saturating_add(value.len());
        if self.overflowed || value.len() > self.maximum.saturating_sub(self.text.len()) {
            self.overflowed = true;
            return Err(fmt::Error);
        }
        self.text.push_str(value);
        Ok(())
    }
}
