// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

//! Borrowed syntax for an inline argv field assignment.

/// A parsed assignment whose source text remains borrowed from its argv item.
pub(in crate::formats::argv) struct InlineAssignment<'a> {
    /// Field name used for policy lookup.
    pub(in crate::formats::argv) field: &'a str,
    /// Unmasked value after the equals sign.
    pub(in crate::formats::argv) value: &'a str,
    /// Original argument prefix through the equals sign.
    pub(in crate::formats::argv) prefix: &'a str,
}
