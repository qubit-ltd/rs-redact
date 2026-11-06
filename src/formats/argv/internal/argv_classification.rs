// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

//! Borrowed classification results shared by argv inspection and rendering.

use std::ffi::OsStr;

use super::inline_assignment::InlineAssignment;
use crate::Sensitivity;

/// Classification of one argv item without rendering or copying its value.
pub(in crate::formats::argv) enum ArgvClassification<'a> {
    /// Preserve the original operating-system string.
    PassThrough(
        /// Original argument borrowed unchanged for rendering without masking.
        &'a OsStr,
    ),
    /// Mask the complete argument at the supplied sensitivity.
    WholeValue {
        /// Original operating-system value.
        value: &'a OsStr,
        /// Policy level for the complete value.
        sensitivity: Sensitivity,
    },
    /// Mask only the value portion of an inline assignment.
    InlineValue {
        /// Parsed borrowed assignment.
        assignment: InlineAssignment<'a>,
        /// Policy level for its value.
        sensitivity: Sensitivity,
    },
    /// Replace a non-Unicode value without attempting lossy parsing.
    OpaqueSecret,
}
