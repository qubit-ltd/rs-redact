// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Error reported when the process-wide default policy is already installed.

use std::{
    error::Error,
    fmt,
};

/// Error returned when a process-wide default policy was already installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GlobalDefaultAlreadySet;

impl fmt::Display for GlobalDefaultAlreadySet {
    /// Formats a concise description of the one-time installation failure.
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
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("the global default redaction policy is already set")
    }
}

impl Error for GlobalDefaultAlreadySet {}
