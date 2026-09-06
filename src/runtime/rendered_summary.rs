// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Conversion from renderer provenance to transaction summaries.

use crate::RedactionCompletion;
use crate::RedactionReason;
use crate::RedactionReasons;
use crate::RedactionSummary;
use crate::RedactionUsage;

/// Converts unpublished renderer provenance into the runtime summary model.
#[must_use]
pub(super) fn rendered_summary(
    completion: RedactionCompletion,
    reasons: RedactionReasons,
) -> RedactionSummary {
    if reasons != RedactionReasons::empty() || completion == RedactionCompletion::Complete {
        return RedactionSummary::from_parts(false, completion, reasons, RedactionUsage::empty());
    }
    match completion {
        RedactionCompletion::Complete => RedactionSummary::complete(),
        RedactionCompletion::Truncated => {
            RedactionSummary::truncated(RedactionReason::TraversalLimitReached)
        }
        RedactionCompletion::Exhausted => {
            RedactionSummary::exhausted(RedactionReason::OutputLimitReached)
        }
    }
}
