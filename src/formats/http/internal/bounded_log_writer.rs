// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP-specific façade over the runtime-owned bounded operation sink.

use super::markers;
use crate::RedactionCompletion;
use crate::RedactionReason;
use crate::runtime::OperationSink;

/// Accumulates log-safe HTTP text through one runtime-owned output allowance.
pub(in crate::formats::http) struct BoundedLogWriter {
    /// Shared bounded storage and marker state for this unpublished rendering.
    sink: OperationSink,
}

impl BoundedLogWriter {
    /// Creates a writer that reserves the HTTP truncation marker when needed.
    ///
    /// # Parameters
    ///
    /// - `max_bytes`: Final escaped output allowance, including any marker.
    /// - `source_truncated`: Whether the source already omitted data.
    ///
    /// # Returns
    ///
    /// An empty sink that reserves a marker when omission requires one.
    #[must_use]
    #[inline]
    pub(in crate::formats::http) fn new(max_bytes: usize, source_truncated: bool) -> Self {
        Self {
            sink: OperationSink::new(max_bytes, markers::TRUNCATED, source_truncated),
        }
    }

    /// Reports whether later payload cannot affect the final operation text.
    ///
    /// # Returns
    ///
    /// Whether later text cannot affect the retained output.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn is_full(&self) -> bool {
        self.sink.is_full()
    }

    /// Returns bytes available before any reserved truncation marker.
    ///
    /// # Returns
    ///
    /// The remaining escaped payload allowance after marker reservation.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn remaining_bytes(&self) -> usize {
        self.sink.remaining_bytes()
    }

    /// Reports whether the output bound, rather than source omission, closed
    /// this writer.
    ///
    /// # Returns
    ///
    /// Whether output capacity caused an omission.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn is_output_truncated(&self) -> bool {
        self.sink.output_truncated()
    }

    /// Writes log-safe text until the operation allowance closes.
    ///
    /// # Parameters
    ///
    /// - `value`: Raw text escaped before admission to the output allowance.
    ///
    /// # Errors
    ///
    /// Propagates an escaping failure. A closed output allowance ignores later
    /// text and returns success; its truncation remains recorded in the sink.
    pub(in crate::formats::http) fn write_str(&mut self, value: &str) -> std::fmt::Result {
        if self.sink.is_full() {
            return Ok(());
        }
        let value = if self.sink.is_truncated() {
            value.strip_suffix(markers::TRUNCATED).unwrap_or(value)
        } else {
            value
        };
        self.sink.write_log_safe(value)
    }

    /// Preserves nested source omission in the final HTTP representation.
    #[inline(always)]
    pub(in crate::formats::http) fn mark_truncated(&mut self) {
        self.sink.mark_truncated();
    }

    /// Preserves source and output failure facts through HTTP publication.
    ///
    /// # Parameters
    ///
    /// - `reason`: Original source failure preserved alongside output
    ///   exhaustion.
    ///
    /// # Returns
    ///
    /// An unpublished operation with final escaped text and independent failure
    /// facts.
    #[inline(always)]
    pub(in crate::formats::http) fn finish_operation(
        self,
        reason: RedactionReason,
    ) -> crate::runtime::RenderedOperation {
        self.sink.finish_with_reason(reason)
    }

    /// Finalizes text and reports whether any source or output was truncated.
    ///
    /// # Returns
    ///
    /// The final escaped text and whether any source or output was omitted.
    pub(in crate::formats::http) fn finish(self) -> (String, bool) {
        let (text, completion, _) = self
            .sink
            .finish_with_reason(RedactionReason::OutputLimitReached)
            .into_parts();
        (text, completion != RedactionCompletion::Complete)
    }
}
