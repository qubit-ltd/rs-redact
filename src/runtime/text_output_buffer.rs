// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished ordered text owned by the text-composition publication path.

use crate::RedactedText;

/// Accumulates unpublished aggregate text for one transaction.
pub(super) struct TextOutputBuffer {
    /// Escaped redacted text retained until transaction publication.
    storage: String,
}

impl TextOutputBuffer {
    /// Creates an empty aggregate text buffer.
    ///
    /// # Returns
    ///
    /// An empty unpublished ordered output buffer.
    #[must_use]
    #[inline(always)]
    pub(super) const fn new() -> Self {
        Self { storage: String::new() }
    }

    /// Appends already-safe text in caller order.
    ///
    /// # Parameters
    ///
    /// - `text`: Already escaped and admitted text to append in caller order.
    #[inline(always)]
    pub(super) fn push(&mut self, text: &str) {
        self.storage.push_str(text);
    }

    /// Consumes the buffer into its opaque published text value.
    ///
    /// # Returns
    ///
    /// The opaque safe text obtained by consuming the unpublished buffer.
    #[must_use]
    #[inline(always)]
    pub(super) fn publish(self) -> RedactedText {
        RedactedText::from_escaped(self.storage)
    }
}
