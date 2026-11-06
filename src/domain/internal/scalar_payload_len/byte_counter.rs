// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Allocation-free sink for counting formatted UTF-8 bytes.

use std::fmt;

/// Counts bytes written through `fmt::Write` without storing the formatted
/// text.
///
/// The default count is zero; writes that would overflow leave it unchanged.
#[derive(Default)]
pub(super) struct ByteCounter {
    /// Total UTF-8 bytes accepted by successful writes so far.
    pub(super) bytes: usize,
}

impl fmt::Write for ByteCounter {
    /// Adds the UTF-8 byte length of a fragment without retaining its contents.
    ///
    /// # Parameters
    ///
    /// - `text`: The borrowed fragment whose bytes are counted.
    ///
    /// # Returns
    ///
    /// `Ok(())` after updating the count.
    ///
    /// # Errors
    ///
    /// Returns `fmt::Error` without changing the count if addition overflows.
    #[inline]
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.bytes = self.bytes.checked_add(text.len()).ok_or(fmt::Error)?;
        Ok(())
    }
}
