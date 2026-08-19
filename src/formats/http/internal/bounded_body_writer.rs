// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded byte sink for structured HTTP body rendering.

use std::io;
use std::io::Write;

/// Accumulates UTF-8 rendering bytes without exceeding a fixed budget.
pub(in crate::formats::http) struct BoundedBodyWriter {
    /// Rendered bytes accepted before the first over-budget write.
    output: Vec<u8>,
    /// Maximum number of rendered bytes retained in `output`.
    max_bytes: usize,
}

impl BoundedBodyWriter {
    /// Creates a byte sink with the specified output limit.
    ///
    /// # Parameters
    ///
    /// * `max_bytes` - Maximum number of bytes accepted by this writer.
    ///
    /// # Returns
    ///
    /// An empty writer that grows only as accepted output is produced.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn new(max_bytes: usize) -> Self {
        Self {
            output: Vec::new(),
            max_bytes,
        }
    }

    /// Converts accepted rendering bytes into UTF-8 text.
    ///
    /// # Returns
    ///
    /// `Some` when all accepted bytes form valid UTF-8, or `None` otherwise.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn into_string(self) -> Option<String> {
        String::from_utf8(self.output).ok()
    }
}

impl Write for BoundedBodyWriter {
    /// Appends one complete byte slice when it fits in the remaining budget.
    ///
    /// # Parameters
    ///
    /// * `buffer` - Complete byte slice to append atomically.
    ///
    /// # Returns
    ///
    /// The number of bytes appended when the complete slice fits.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::WriteZero`] after recording overflow when the
    /// complete slice would exceed the configured limit. No partial slice is
    /// retained, so successful JSON serialization always retains valid UTF-8.
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.output.len().saturating_add(buffer.len()) > self.max_bytes {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        self.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    /// Flushes this in-memory writer.
    ///
    /// # Returns
    ///
    /// `Ok(())` because buffered bytes are retained in memory.
    ///
    /// # Errors
    ///
    /// This in-memory flush operation never returns an error.
    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
