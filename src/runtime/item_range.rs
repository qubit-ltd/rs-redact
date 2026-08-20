// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Ranges identifying item text inside one transaction output arena.

use std::ops::Range;

use crate::RedactionSummary;

/// Associates one staged item range with its operation-local summary.
pub(super) struct ItemRange {
    pub(super) range: Range<usize>,
    pub(super) summary: RedactionSummary,
}

impl ItemRange {
    /// Creates a staged item descriptor for later atomic publication.
    #[must_use]
    pub(super) const fn new(range: Range<usize>, summary: RedactionSummary) -> Self {
        Self { range, summary }
    }
}
