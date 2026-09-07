// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Failure facts independent of output capacity and publication.

use crate::RedactionReason;

/// Distinguishes a rejected capture write from a formatter's own error.
#[must_use]
pub(in crate::runtime) enum ScalarFailure {
    /// A submitted UTF-8 chunk did not fit the remaining input allowance.
    InputLimit,
    /// Formatting returned an error without any rejected capture write.
    FormatterFailure,
}

impl ScalarFailure {
    /// Returns the observed failure's provenance without inferring output
    /// state.
    ///
    /// # Returns
    ///
    /// The input-limit or formatting-failure reason represented by this value.
    #[must_use]
    #[inline(always)]
    pub(in crate::runtime) const fn reason(&self) -> RedactionReason {
        match self {
            Self::InputLimit => RedactionReason::InputLimitReached,
            Self::FormatterFailure => RedactionReason::FormattingFailed,
        }
    }
}
