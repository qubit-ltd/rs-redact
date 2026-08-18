// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Streaming construction of bounded redacted argv diagnostics.

use super::RedactedArgv;
use crate::RedactedText;

/// Streams a byte-bounded argv rendering without retaining every token.
pub(super) struct RedactedArgvBuilder {
    /// Escaped destination for the complete debug-style list.
    writer: String,
    /// Whether at least one item has been written.
    has_item: bool,
    /// Whether the closing delimiter has already been appended.
    closed: bool,
}

impl RedactedArgvBuilder {
    /// Starts an empty argv rendering with the supplied diagnostic budget.
    ///
    /// # Parameters
    ///
    /// * `budget` - Input and output limits for the diagnostic rendering.
    ///
    /// # Returns
    ///
    /// An empty byte-bounded argv rendering builder.
    #[must_use]
    #[inline]
    pub(super) fn new() -> Self {
        Self {
            writer: "[".to_owned(),
            has_item: false,
            closed: false,
        }
    }

    /// Appends one already redacted token to the bounded debug-style list.
    ///
    /// # Parameters
    ///
    /// * `item` - Already-redacted token to append.
    ///
    /// # Returns
    ///
    /// `true` when additional tokens can still be written, or `false` after
    /// output truncation.
    #[inline]
    pub(super) fn push(&mut self, item: &str) -> bool {
        if self.has_item {
            self.writer.push_str(", ");
        }
        self.writer.push_str(&format!("{item:?}"));
        self.has_item = true;
        true
    }

    /// Appends the closing list delimiter before the builder is consumed.
    #[inline(always)]
    pub(super) fn close(&mut self) {
        if !self.closed {
            self.writer.push(']');
            self.closed = true;
        }
    }

    /// Completes the bounded argv rendering and maps local omission.
    ///
    /// # Parameters
    ///
    /// * `locally_truncated` - Whether an admitted item mask was shortened
    ///   before it reached this builder.
    ///
    /// # Returns
    ///
    /// The final log-safe argv rendering. Either a locally shortened mask or
    /// builder output truncation produces
    /// [`crate::RedactionCompletion::Truncated`].
    #[inline]
    #[must_use]
    pub(super) fn finish(mut self, locally_truncated: bool) -> RedactedArgv {
        self.close();
        let truncated = locally_truncated;
        let rendered = RedactedText::from_escaped(self.writer);
        if truncated {
            RedactedArgv::truncated(rendered)
        } else {
            RedactedArgv::complete(rendered)
        }
    }
}
