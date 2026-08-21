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
    pub(in crate::formats::http) fn new(max_bytes: usize, source_truncated: bool) -> Self {
        Self {
            sink: OperationSink::new(max_bytes, markers::TRUNCATED, source_truncated),
        }
    }

    /// Writes log-safe text until the operation allowance closes.
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

    /// Reports whether later payload cannot affect the final operation text.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn is_full(&self) -> bool {
        self.sink.is_full()
    }

    /// Returns bytes available before any reserved truncation marker.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn remaining_bytes(&self) -> usize {
        self.sink.remaining_bytes()
    }

    /// Preserves nested source omission in the final HTTP representation.
    pub(in crate::formats::http) fn mark_truncated(&mut self) {
        self.sink.mark_truncated();
    }

    /// Reports whether the output bound, rather than source omission, closed
    /// this writer.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn is_output_truncated(&self) -> bool {
        self.sink.output_truncated()
    }

    /// Finalizes text and reports whether any source or output was truncated.
    pub(in crate::formats::http) fn finish(self) -> (String, bool) {
        let (text, completion, _) = self
            .sink
            .finish_with_reason(RedactionReason::OutputLimitReached)
            .into_parts();
        (text, completion != RedactionCompletion::Complete)
    }
}
