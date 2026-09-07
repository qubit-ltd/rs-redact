// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Conversion from renderer provenance to transaction summaries.

use crate::RedactionCompletion;
use crate::RedactionReasons;
use crate::RedactionSummary;
use crate::RedactionUsage;

/// Converts unpublished renderer provenance into the runtime summary model.
///
/// # Parameters
///
/// - `completion`: Renderer completion state.
/// - `reasons`: Renderer provenance, including an output-limit reason for
///   exhaustion.
///
/// # Returns
///
/// A summary with neutral resource usage for merging into runtime accounting.
///
/// # Panics
///
/// In debug builds, panics if `Exhausted` lacks an output-limit reason.
#[must_use]
#[inline(always)]
pub(super) fn rendered_summary(completion: RedactionCompletion, reasons: RedactionReasons) -> RedactionSummary {
    RedactionSummary::from_parts(false, completion, reasons, RedactionUsage::empty())
}
