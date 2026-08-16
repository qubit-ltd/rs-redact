// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Streaming construction of bounded redacted argv diagnostics.

use std::fmt::Write as _;

use super::RedactedArgv;
use crate::InputOutputLimit;
use crate::LogOutputLimit;
use crate::LogSafeText;
use crate::text::internal::BoundedLogEscapeWriter;

/// Streams a byte-bounded argv rendering without retaining every token.
pub(super) struct RedactedArgvBuilder {
    /// Escaped destination for the complete debug-style list.
    writer: BoundedLogEscapeWriter,
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
    pub(super) fn new(budget: InputOutputLimit) -> Self {
        let limit = LogOutputLimit::from(budget);
        let mut writer = BoundedLogEscapeWriter::new(limit);
        let _ = writer.write_str("[");
        Self {
            writer,
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
            let _ = self.writer.write_str(", ");
        }
        let _ = write!(self.writer, "{item:?}");
        self.has_item = true;
        !self.writer.is_truncated()
    }

    /// Returns the current escaped output length.
    #[inline(always)]
    pub(super) fn len(&self) -> usize {
        self.writer.len()
    }

    /// Reports whether the bounded writer has finalized its truncation marker.
    #[must_use]
    #[inline(always)]
    pub(super) fn is_truncated(&self) -> bool {
        self.writer.is_truncated()
    }

    /// Appends the closing list delimiter before the builder is consumed.
    #[inline(always)]
    pub(super) fn close(&mut self) {
        if !self.closed && !self.writer.is_truncated() {
            let _ = self.writer.write_str("]");
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
        let truncated = locally_truncated || self.writer.is_truncated();
        let rendered = LogSafeText::from_escaped(self.writer.finish().into());
        if truncated {
            RedactedArgv::truncated(rendered)
        } else {
            RedactedArgv::complete(rendered)
        }
    }
}
