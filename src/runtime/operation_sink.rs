// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime-owned bounded storage for one unpublished rendering operation.

use std::fmt;

use super::rendered_operation::RenderedOperation;
use crate::RedactionCompletion;
use crate::RedactionReason;
use crate::RedactionReasons;

/// Accumulates one log-safe rendering without exceeding its admitted allowance.
pub(crate) struct OperationSink {
    output: String,
    marker_boundary: usize,
    maximum: usize,
    marker: &'static str,
    truncated: bool,
    output_truncated: bool,
    completion: RedactionCompletion,
    reasons: RedactionReasons,
}

impl OperationSink {
    /// Creates a complete operation through the runtime-owned result boundary.
    #[must_use]
    pub(crate) fn complete(text: impl Into<String>) -> Self {
        Self::from_rendered(text.into(), RedactionCompletion::Complete, RedactionReasons::empty())
    }

    /// Creates a complete operation with non-degrading provenance.
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    #[must_use]
    pub(crate) fn complete_with_reason(text: impl Into<String>, reason: RedactionReason) -> Self {
        Self::from_rendered(
            text.into(),
            RedactionCompletion::Complete,
            RedactionReasons::empty().with(reason),
        )
    }

    /// Creates a truncated operation through the runtime-owned result boundary.
    #[must_use]
    pub(crate) fn truncated(text: impl Into<String>, reason: RedactionReason) -> Self {
        Self::from_rendered(
            text.into(),
            RedactionCompletion::Truncated,
            RedactionReasons::empty().with(reason),
        )
    }

    /// Creates an exhausted operation through the runtime-owned result
    /// boundary.
    #[must_use]
    pub(crate) fn exhausted(text: impl Into<String>, reason: RedactionReason) -> Self {
        Self::from_rendered(
            text.into(),
            RedactionCompletion::Exhausted,
            RedactionReasons::empty().with(reason),
        )
    }
    /// Creates an empty sink with `maximum` final bytes and an optional marker.
    #[must_use]
    pub(crate) fn new(maximum: usize, marker: &'static str, source_truncated: bool) -> Self {
        Self {
            output: String::new(),
            marker_boundary: 0,
            maximum,
            marker,
            truncated: source_truncated,
            output_truncated: false,
            completion: RedactionCompletion::Complete,
            reasons: RedactionReasons::empty(),
        }
    }

    /// Writes a complete already-safe atom, retaining it only when it fits.
    pub(crate) fn write_atom(&mut self, atom: &str) -> bool {
        if self.is_full() || self.output.len().saturating_add(atom.len()) > self.payload_limit() {
            self.truncate_for_output();
            return false;
        }
        self.output.push_str(atom);
        if self.output.len() <= self.maximum.saturating_sub(self.marker.len()) {
            self.marker_boundary = self.output.len();
        }
        true
    }

    /// Writes text after applying the common log-control escape rules.
    pub(crate) fn write_log_safe(&mut self, value: &str) -> fmt::Result {
        for character in value.chars() {
            let mut encoded = [0_u8; 12];
            let atom = crate::output::log_escape::encode_log_safe_character(character, &mut encoded)?;
            if !self.write_atom(atom) {
                break;
            }
        }
        Ok(())
    }

    /// Marks input or a nested renderer as truncated while reserving the
    /// marker.
    #[cfg(any(feature = "http", feature = "uri"))]
    pub(crate) fn mark_truncated(&mut self) {
        self.truncated = true;
        self.output.truncate(self.marker_boundary);
    }

    /// Returns whether source or output omission requires a final marker.
    #[must_use]
    #[inline(always)]
    #[cfg(feature = "http")]
    pub(crate) const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns whether additional payload cannot affect the final output.
    #[must_use]
    #[inline(always)]
    pub(crate) fn is_full(&self) -> bool {
        self.output_truncated || (self.truncated && self.output.len() >= self.payload_limit())
    }

    /// Returns the remaining payload bytes before a required marker.
    #[must_use]
    #[inline(always)]
    #[cfg(feature = "http")]
    pub(crate) fn remaining_bytes(&self) -> usize {
        self.payload_limit().saturating_sub(self.output.len())
    }

    /// Returns whether the output allowance, rather than source provenance,
    /// truncated text.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn output_truncated(&self) -> bool {
        self.output_truncated
    }

    /// Adds provenance without weakening the current completion state.
    #[must_use]
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    pub(crate) fn with_reason(mut self, reason: RedactionReason) -> Self {
        self.reasons = self.reasons.with(reason);
        self
    }

    /// Finalizes a pre-rendered operation through the runtime-owned boundary.
    #[must_use]
    pub(crate) fn finish(self) -> RenderedOperation {
        RenderedOperation::from_parts(self.output, self.completion, self.reasons)
    }

    /// Finalizes bounded text and turns sink-owned state into one operation.
    #[must_use]
    pub(crate) fn finish_with_reason(mut self, reason: RedactionReason) -> RenderedOperation {
        if self.truncated {
            if self.maximum < self.marker.len() {
                self.output.clear();
                return RenderedOperation::from_parts(
                    self.output,
                    RedactionCompletion::Exhausted,
                    RedactionReasons::empty().with(reason),
                );
            }
            self.output.truncate(self.marker_boundary);
            self.output.push_str(self.marker);
            return RenderedOperation::from_parts(
                self.output,
                RedactionCompletion::Truncated,
                RedactionReasons::empty().with(reason),
            );
        }
        RenderedOperation::from_parts(self.output, self.completion, self.reasons)
    }

    /// Returns the payload maximum after reserving a marker when necessary.
    #[inline(always)]
    fn payload_limit(&self) -> usize {
        if self.truncated {
            self.maximum.saturating_sub(self.marker.len())
        } else {
            self.maximum
        }
    }

    /// Records output overflow and preserves the last marker-safe boundary.
    fn truncate_for_output(&mut self) {
        self.truncated = true;
        self.output_truncated = true;
        self.output.truncate(self.marker_boundary);
    }

    /// Wraps text already bounded by a format algorithm for runtime
    /// finalization.
    fn from_rendered(text: String, completion: RedactionCompletion, reasons: RedactionReasons) -> Self {
        let maximum = text.len();
        Self {
            output: text,
            marker_boundary: maximum,
            maximum,
            marker: "",
            truncated: false,
            output_truncated: false,
            completion,
            reasons,
        }
    }
}
