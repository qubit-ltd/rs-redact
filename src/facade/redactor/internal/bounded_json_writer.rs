// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Final encoded JSON capacity, independent of logical Serde payload.

use std::io;
use std::io::Write;

/// Retains encoded bytes only while every serializer write fits atomically.
pub(in crate::facade::redactor) struct BoundedJsonWriter {
    /// Encoded bytes retained for publication only after successful
    /// serialization.
    bytes: Vec<u8>,
    /// Maximum final JSON bytes, including serializer syntax and escaping.
    maximum: usize,
    /// A rejected chunk permanently prevents publication of partial encoding.
    rejected: bool,
}

impl BoundedJsonWriter {
    /// Creates empty storage without preallocating the full configured ceiling.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Final encoded byte ceiling, including syntax and escaping.
    ///
    /// # Returns
    ///
    /// Empty storage with a small capped initial allocation and no rejection.
    #[must_use]
    #[inline]
    pub(in crate::facade::redactor) fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(4096)),
            maximum,
            rejected: false,
        }
    }

    /// Consumes successfully encoded storage for UTF-8 validation and
    /// publication.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::WriteZero`] if any encoded chunk was rejected,
    /// even if custom serialization suppressed the original write error.
    ///
    /// # Returns
    ///
    /// The complete retained encoding only if every submitted chunk was
    /// accepted.
    #[inline]
    pub(in crate::facade::redactor) fn into_bytes(self) -> io::Result<Vec<u8>> {
        if self.rejected {
            Err(output_limit_error())
        } else {
            Ok(self.bytes)
        }
    }
}

impl Write for BoundedJsonWriter {
    /// Rejects the complete write before any bytes can exceed the final limit.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::WriteZero`] on this or any previous rejection.
    ///
    /// # Parameters
    ///
    /// - `bytes`: One atomic encoded chunk offered by the serializer.
    ///
    /// # Returns
    ///
    /// The complete chunk length after retaining all its bytes.
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.rejected || bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            self.rejected = true;
            return Err(output_limit_error());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    /// In-memory storage has no external buffer to flush.
    #[inline(always)]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Creates the stable error shared by write rejection and final publication.
///
/// # Returns
///
/// A value-free WriteZero error identifying the final JSON byte limit.
#[must_use]
#[inline]
fn output_limit_error() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "redaction JSON output budget exceeded")
}
