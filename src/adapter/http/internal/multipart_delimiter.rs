// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Multipart delimiter classification.

/// Kind of multipart delimiter line.
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
    /// * `boundary` - Boundary parameter without the leading `--`.
    ///
    /// # Returns
    ///
    /// Delimiter kind for an exact delimiter line.
    pub(in crate::adapter::http) fn classify(
        line: &str,
        boundary: &str,
    ) -> Option<Self> {
        let delimiter = format!("--{boundary}");
        if line == delimiter {
            Some(Self::Part)
        } else if line == format!("{delimiter}--") {
            Some(Self::Closing)
        } else {
            None
        }
    }
}
