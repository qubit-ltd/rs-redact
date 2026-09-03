// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Errors raised when resolving a batch capability.

use std::fmt;

/// Error returned when a batch output cannot resolve a handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedactionBatchHandleError {
    /// The handle was created by a different batch.
    DifferentBatch,
    /// The handle index is outside the published batch item range.
    MissingItem,
}

impl fmt::Display for RedactionBatchHandleError {
    /// Renders a stable diagnostic that contains no protected text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DifferentBatch => "the handle belongs to a different batch",
            Self::MissingItem => "the handle does not identify a published item",
        })
    }
}

impl std::error::Error for RedactionBatchHandleError {}
