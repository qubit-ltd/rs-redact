// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Owned JSON output and provenance used by bounded serialization.

/// JSON output paired with truncation or invalid-source provenance.
///
/// Safe fallback text may require caller-side bounding before publication.
pub(in crate::formats::json) enum BoundedJsonRedaction {
    /// Serialization completed without budget omission.
    Complete(
        /// Complete compact JSON text, or an opaque mask for invalid UTF-8.
        String,
    ),
    /// A non-empty safe substitute represents budget-omitted content.
    Truncated(
        /// Safe fallback or prefix retained after omission.
        String,
    ),
    /// A syntactically invalid source was replaced without exposing it.
    Invalid(
        /// Opaque replacement emitted instead of invalid source text.
        String,
    ),
}

impl BoundedJsonRedaction {
    /// Consumes this result into its text and truncation provenance.
    ///
    /// # Returns
    ///
    /// The owned output text, whether content was truncated, and whether
    /// invalid source text was replaced, in that order. The two flags are
    /// mutually exclusive; both are false for complete output.
    #[must_use]
    #[inline]
    pub(in crate::formats::json) fn into_parts(self) -> (String, bool, bool) {
        match self {
            Self::Complete(text) => (text, false, false),
            Self::Truncated(text) => (text, true, false),
            Self::Invalid(text) => (text, false, true),
        }
    }
}
