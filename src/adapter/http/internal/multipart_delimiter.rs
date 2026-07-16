// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Multipart delimiter classification.

/// Kind of multipart delimiter line.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::adapter::http) enum MultipartDelimiter {
    /// Delimiter before a regular part.
    Part,
    /// Final closing delimiter.
    Closing,
}

impl MultipartDelimiter {
    /// Classifies one complete multipart delimiter line.
    ///
    /// # Parameters
    ///
    /// * `line` - Logical line without a trailing line ending.
    /// * `delimiter` - Precomputed delimiter including the leading `--`.
    /// * `closing_delimiter` - Precomputed final delimiter ending in `--`.
    ///
    /// # Returns
    ///
    /// Delimiter kind for an exact delimiter line.
    #[inline]
    pub(in crate::adapter::http) fn classify(
        line: &str,
        delimiter: &str,
        closing_delimiter: &str,
    ) -> Option<Self> {
        if line == delimiter {
            Some(Self::Part)
        } else if line == closing_delimiter {
            Some(Self::Closing)
        } else {
            None
        }
    }
}
