// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Validation errors for truncated HTTP body captures.

use std::{
    error::Error,
    fmt::{
        self,
        Display,
        Formatter,
    },
};

/// Reports inconsistent source-length metadata for a body capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyCaptureError {
    /// A truncated capture claimed a total no larger than captured bytes.
    InvalidTotalLength {
        /// Number of bytes present in the capture.
        captured: usize,
        /// Rejected claimed total source length.
        total: usize,
    },
}

impl Display for BodyCaptureError {
    /// Writes a concise description of the invalid capture metadata.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result from writing the error description.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination rejects a write.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTotalLength { captured, total } => write!(
                formatter,
                "truncated body total length {total} must exceed {captured} captured bytes",
            ),
        }
    }
}

impl Error for BodyCaptureError {}
