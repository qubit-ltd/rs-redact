// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Source-length metadata for a captured HTTP body.

/// Describes the source length behind caller-provided HTTP body bytes.
///
/// Use [`Self::Known`] when the total source byte length is exact, including
/// when it equals the captured length. Use [`Self::UnknownTruncated`] when the
/// caller knows additional bytes were omitted but cannot determine the exact
/// total length.
#[must_use]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySourceLength {
    /// Exact total source byte length.
    Known(usize),
    /// The source is truncated and its exact total length is unknown.
    UnknownTruncated,
}

impl BodySourceLength {
    /// Resolves exact source length and truncation state for captured bytes.
    ///
    /// # Parameters
    ///
    /// * `captured_len` - Number of source bytes available to the sanitizer.
    ///
    /// # Returns
    ///
    /// Exact source length when known and whether source bytes were omitted.
    #[must_use]
    #[inline(always)]
    pub(super) const fn resolve(
        self,
        captured_len: usize,
    ) -> (Option<usize>, bool) {
        match self {
            Self::Known(source_len) => {
                let source_len = if source_len < captured_len {
                    captured_len
                } else {
                    source_len
                };
                (Some(source_len), source_len > captured_len)
            }
            Self::UnknownTruncated => (None, true),
        }
    }
}
