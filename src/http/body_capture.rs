// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Checked borrowed input for HTTP body redaction.

use super::BodyCaptureError;

/// Borrowed HTTP body bytes with truthful source-length metadata.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyCapture<'a> {
    /// Source bytes available to the redactor before its hard input budget.
    bytes: &'a [u8],
    /// Exact total source length, or `None` when omitted length is unknown.
    total_len: Option<usize>,
    /// Whether the source already omitted bytes before reaching the redactor.
    source_truncated: bool,
}

impl<'a> BodyCapture<'a> {
    /// Creates a capture containing the complete source body.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Complete source body bytes.
    ///
    /// # Returns
    ///
    /// A capture whose total length equals the borrowed slice length.
    #[inline(always)]
    pub const fn complete(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            total_len: Some(bytes.len()),
            source_truncated: false,
        }
    }

    /// Creates a capture known to omit source bytes.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Captured prefix of the source body.
    /// * `total_len` - Exact complete source length, or `None` when unknown.
    ///
    /// # Returns
    ///
    /// A checked truncated capture.
    ///
    /// # Errors
    ///
    /// Returns [`BodyCaptureError::InvalidTotalLength`] when a known total is
    /// less than or equal to the captured slice length.
    #[inline]
    pub const fn truncated(
        bytes: &'a [u8],
        total_len: Option<usize>,
    ) -> Result<Self, BodyCaptureError> {
        if let Some(total) = total_len
            && total <= bytes.len()
        {
            return Err(BodyCaptureError::InvalidTotalLength {
                captured: bytes.len(),
                total,
            });
        }
        Ok(Self {
            bytes,
            total_len,
            source_truncated: true,
        })
    }

    /// Returns the body bytes available before the redactor's hard budget.
    ///
    /// # Returns
    ///
    /// The borrowed captured byte slice.
    #[inline(always)]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the number of captured bytes.
    ///
    /// # Returns
    ///
    /// The borrowed slice length.
    #[inline(always)]
    pub const fn captured_len(self) -> usize {
        self.bytes.len()
    }

    /// Returns the complete source length when known.
    ///
    /// # Returns
    ///
    /// `Some(total)` for an exact length, or `None` for a truncated capture
    /// whose omitted byte count is unknown.
    #[inline(always)]
    pub const fn total_len(self) -> Option<usize> {
        self.total_len
    }

    /// Returns the number of source bytes omitted before capture.
    ///
    /// # Returns
    ///
    /// `Some(0)` for complete input, `Some(count)` for a known truncated
    /// total, or `None` when the total length is unknown.
    #[inline(always)]
    pub const fn omitted_len(self) -> Option<usize> {
        match self.total_len {
            Some(total) => Some(total - self.bytes.len()),
            None => None,
        }
    }

    /// Reports whether source bytes were omitted before capture.
    ///
    /// # Returns
    ///
    /// `true` only for captures created with [`Self::truncated`].
    #[inline(always)]
    pub const fn is_source_truncated(self) -> bool {
        self.source_truncated
    }
}
