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
    /// Log-safe payload retained for the unpublished operation.
    output: String,
    /// Last byte boundary at which the truncation marker still fits.
    marker_boundary: usize,
    /// Maximum bytes the operation may retain, including its marker.
    maximum: usize,
    /// Static safe marker appended when payload output is omitted.
    marker: &'static str,
    /// Whether source metadata or rendering indicates omission.
    truncated: bool,
    /// Whether the output ceiling rejected any rendered text.
    output_truncated: bool,
    /// Strongest completion state accumulated by this operation.
    completion: RedactionCompletion,
    /// Machine-readable provenance accumulated by this operation.
    reasons: RedactionReasons,
}

impl OperationSink {
    /// Creates a complete operation through the runtime-owned result boundary.
    ///
    /// # Parameters
    ///
    /// - `text`: Already safe text bounded by the caller's format algorithm.
    ///
    /// # Returns
    ///
    /// A sink wrapping the supplied complete rendering.
    #[must_use]
    #[inline(always)]
    pub(crate) fn complete(text: impl Into<String>) -> Self {
        Self::from_rendered(text.into(), RedactionCompletion::Complete, RedactionReasons::empty())
    }

    /// Creates a complete operation with non-degrading provenance.
    ///
    /// # Parameters
    ///
    /// - `text`: Already safe text bounded by the caller's format algorithm.
    /// - `reason`: Observed provenance for this rendering.
    ///
    /// # Returns
    ///
    /// A sink wrapping the supplied rendering and its completion facts.
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    #[must_use]
    #[inline(always)]
    pub(crate) fn complete_with_reason(text: impl Into<String>, reason: RedactionReason) -> Self {
        Self::from_rendered(
            text.into(),
            RedactionCompletion::Complete,
            RedactionReasons::empty().with(reason),
        )
    }

    /// Creates a truncated operation through the runtime-owned result boundary.
    ///
    /// # Parameters
    ///
    /// - `text`: Already safe text bounded by the caller's format algorithm.
    /// - `reason`: Observed provenance for this rendering.
    ///
    /// # Returns
    ///
    /// A truncated rendering, except empty text caused by `OutputLimitReached`
    /// becomes exhausted. Other causes preserve truncated completion even
    /// when their supplied text is empty.
    #[must_use]
    #[inline]
    pub(crate) fn truncated(text: impl Into<String>, reason: RedactionReason) -> Self {
        let text = text.into();
        let completion = if text.is_empty() && reason == RedactionReason::OutputLimitReached {
            RedactionCompletion::Exhausted
        } else {
            RedactionCompletion::Truncated
        };
        Self::from_rendered(text, completion, RedactionReasons::empty().with(reason))
    }

    /// Creates an exhausted operation through the runtime-owned result
    /// boundary.
    ///
    /// # Parameters
    ///
    /// - `text`: Already safe text bounded by the caller's format algorithm.
    ///
    /// # Returns
    ///
    /// A sink wrapping the supplied exhausted rendering.
    #[must_use]
    #[inline(always)]
    pub(crate) fn exhausted(text: impl Into<String>) -> Self {
        Self::from_rendered(
            text.into(),
            RedactionCompletion::Exhausted,
            RedactionReasons::empty().with(RedactionReason::OutputLimitReached),
        )
    }

    /// Creates an empty sink with `maximum` final bytes and an optional marker.
    ///
    /// # Parameters
    ///
    /// - `maximum`: Final escaped byte limit, including a required marker.
    /// - `marker`: Trusted static fallback marker.
    /// - `source_truncated`: Whether the source already requires a final
    ///   marker.
    ///
    /// # Returns
    ///
    /// An empty bounded sink with independent source and output truncation
    /// state.
    #[must_use]
    #[inline(always)]
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

    /// Wraps text already bounded by a format algorithm for runtime
    /// finalization.
    ///
    /// # Parameters
    ///
    /// - `text`: Already bounded, escaped payload.
    /// - `completion`: Completion determined by the format algorithm.
    /// - `reasons`: Observed rendering provenance.
    ///
    /// # Returns
    ///
    /// A sink retaining the existing payload without further marker insertion.
    #[must_use]
    #[inline]
    fn from_rendered(text: String, completion: RedactionCompletion, reasons: RedactionReasons) -> Self {
        let maximum = text.len();
        Self {
            output: text,
            marker_boundary: maximum,
            maximum,
            marker: "",
            truncated: false,
            output_truncated: reasons.contains(RedactionReason::OutputLimitReached),
            completion,
            reasons,
        }
    }

    /// Returns whether source or output omission requires a final marker.
    ///
    /// # Returns
    ///
    /// Whether source or output omission requires the configured marker.
    #[must_use]
    #[inline(always)]
    #[cfg(feature = "http")]
    pub(crate) const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns whether additional payload cannot affect the final output.
    ///
    /// # Returns
    ///
    /// Whether later payload can no longer change the retained output.
    #[must_use]
    #[inline(always)]
    pub(crate) fn is_full(&self) -> bool {
        self.output_truncated || (self.truncated && self.output.len() >= self.payload_limit())
    }

    /// Returns the remaining payload bytes before a required marker.
    ///
    /// # Returns
    ///
    /// Remaining escaped payload bytes after any marker reservation.
    #[must_use]
    #[inline(always)]
    #[cfg(feature = "http")]
    pub(crate) fn remaining_bytes(&self) -> usize {
        self.payload_limit().saturating_sub(self.output.len())
    }

    /// Returns whether the output allowance, rather than source provenance,
    /// truncated text.
    ///
    /// # Returns
    ///
    /// Whether the output limit rejected payload.
    #[must_use]
    #[inline(always)]
    #[cfg(feature = "http")]
    pub(crate) const fn output_truncated(&self) -> bool {
        self.output_truncated
    }

    /// Writes a complete already-safe atom, retaining it only when it fits.
    ///
    /// # Parameters
    ///
    /// - `atom`: One complete, already escaped output unit.
    ///
    /// # Returns
    ///
    /// `true` if the complete atom was retained; `false` records output closure
    /// and discards any suffix needed to reserve the marker.
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
    ///
    /// # Parameters
    ///
    /// - `value`: Raw text to escape one Unicode scalar at a time.
    ///
    /// # Errors
    ///
    /// Propagates a character-encoding error. Capacity rejection is recorded in
    /// the sink and stops iteration; it does not itself return an error here.
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
    #[inline]
    pub(crate) fn mark_truncated(&mut self) {
        self.truncated = true;
        self.output.truncate(self.marker_boundary);
    }

    /// Adds provenance without weakening the current completion state.
    ///
    /// # Parameters
    ///
    /// - `reason`: Additional non-degrading provenance.
    ///
    /// # Returns
    ///
    /// This sink with the reason unioned into its existing set.
    #[must_use]
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    #[inline(always)]
    pub(crate) fn with_reason(mut self, reason: RedactionReason) -> Self {
        self.reasons = self.reasons.with(reason);
        self
    }

    /// Finalizes a pre-rendered operation through the runtime-owned boundary.
    ///
    /// # Returns
    ///
    /// The pre-rendered operation; use `finish_with_reason` for an active
    /// bounded sink.
    #[must_use]
    #[inline(always)]
    pub(crate) fn finish(self) -> RenderedOperation {
        RenderedOperation::from_parts(self.output, self.completion, self.reasons, self.output_truncated)
    }

    /// Finalizes bounded text and turns sink-owned state into one operation.
    ///
    /// # Parameters
    ///
    /// - `reason`: Cause used when source or output omission requires a marker.
    ///
    /// # Returns
    ///
    /// The bounded operation, preserving the original cause and adding an
    /// output-limit reason and closure when the sink or marker cannot fit.
    #[must_use]
    pub(crate) fn finish_with_reason(mut self, reason: RedactionReason) -> RenderedOperation {
        if self.truncated {
            self.reasons = self.reasons.with(reason);
            if self.output_truncated || self.maximum < self.marker.len() {
                self.reasons = self.reasons.with(RedactionReason::OutputLimitReached);
            }
            if self.maximum < self.marker.len() {
                self.output.clear();
                return RenderedOperation::from_parts(self.output, RedactionCompletion::Exhausted, self.reasons, true);
            }
            self.output.truncate(self.marker_boundary);
            self.output.push_str(self.marker);
            let output_closed = self.output_truncated || reason == RedactionReason::OutputLimitReached;
            return RenderedOperation::from_parts(
                self.output,
                RedactionCompletion::Truncated,
                self.reasons,
                output_closed,
            );
        }
        RenderedOperation::from_parts(self.output, self.completion, self.reasons, self.output_truncated)
    }

    /// Returns the payload maximum after reserving a marker when necessary.
    ///
    /// # Returns
    ///
    /// The escaped byte ceiling for payload, excluding a required marker.
    #[must_use]
    #[inline(always)]
    fn payload_limit(&self) -> usize {
        if self.truncated {
            self.maximum.saturating_sub(self.marker.len())
        } else {
            self.maximum
        }
    }

    /// Records output overflow and preserves the last marker-safe boundary.
    #[inline]
    fn truncate_for_output(&mut self) {
        self.truncated = true;
        self.output_truncated = true;
        self.output.truncate(self.marker_boundary);
    }
}

impl fmt::Write for OperationSink {
    /// Stops a formatter after its first rejected escaped output atom.
    ///
    /// # Parameters
    ///
    /// - `value`: Raw formatter text to escape and retain under the allowance.
    ///
    /// # Errors
    ///
    /// Returns `fmt::Error` on any output rejection, including a previous
    /// rejection, or propagates an escaping error.
    #[inline]
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.write_log_safe(value)?;
        if self.output_truncated { Err(fmt::Error) } else { Ok(()) }
    }
}
