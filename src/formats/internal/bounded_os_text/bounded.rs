// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Formatting sink for bounded operating-system string capture.

use std::fmt::Error;
use std::fmt::Result as FmtResult;
use std::fmt::Write;

use super::append_bounded;

/// Appends complete formatting chunks and records byte-limit rejection.
///
/// This sink is used only on platforms without Unix or Windows string access.
pub(super) struct Bounded<'a> {
    /// Destination for accepted UTF-8 chunks.
    pub(super) output: &'a mut String,
    /// Maximum total byte length of the destination.
    pub(super) maximum: usize,
    /// Whether a write was rejected because it exceeded the byte limit.
    pub(super) exceeded: bool,
}

impl Write for Bounded<'_> {
    /// Appends a complete chunk if it fits, recording a rejected write.
    ///
    /// # Parameters
    ///
    /// - `text`: The complete UTF-8 chunk to append or reject.
    ///
    /// # Returns
    ///
    /// Success after appending the complete chunk.
    ///
    /// # Errors
    ///
    /// Returns a formatting error when the chunk exceeds the total byte limit;
    /// the output is unchanged and `exceeded` is set to `true`.
    fn write_str(&mut self, text: &str) -> FmtResult {
        if !append_bounded(self.output, text, self.maximum) {
            self.exceeded = true;
            return Err(Error);
        }
        Ok(())
    }
}
