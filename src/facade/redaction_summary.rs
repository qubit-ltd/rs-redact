// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Machine-readable redaction summaries.

use super::RedactionReason;
use super::RedactionReasons;
use super::RedactionUsage;
use crate::output::RedactionCompletion;

/// Machine-readable summary of one redaction operation.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionCompletion;
/// use qubit_redact::Redactor;
///
/// let output = Redactor::standard().redact_field("password", "raw-secret");
/// assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
/// assert!(!output.summary().is_redaction_disabled());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionSummary {
    /// Whether the operation intentionally bypassed redaction.
    redaction_disabled: bool,
    /// Final completion state of the operation.
    completion: RedactionCompletion,
    /// Reasons explaining degraded completion.
    reasons: RedactionReasons,
    /// Resource accounting captured by the operation.
    usage: RedactionUsage,
}

impl RedactionSummary {
    /// Creates a summary from runtime-owned completion, reasons, and usage.
    ///
    /// # Parameters
    ///
    /// - `redaction_disabled`: Whether the operation intentionally bypassed
    ///   redaction.
    /// - `completion`: Final state of the safe representation.
    /// - `reasons`: Independent causes recorded by the operation.
    /// - `usage`: Completed resource measurements.
    ///
    /// # Returns
    ///
    /// A summary retaining the supplied completion, reasons, and accounting.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn from_parts(
        redaction_disabled: bool,
        completion: RedactionCompletion,
        reasons: RedactionReasons,
        usage: RedactionUsage,
    ) -> Self {
        Self {
            redaction_disabled,
            completion,
            reasons,
            usage,
        }
    }

    /// Creates a degraded summary.
    ///
    /// # Parameters
    ///
    /// - `reason`: Cause of the degraded safe representation.
    ///
    /// # Returns
    ///
    /// A truncated summary with the supplied reason and empty accounting.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn truncated(reason: RedactionReason) -> Self {
        Self {
            redaction_disabled: false,
            completion: RedactionCompletion::Truncated,
            reasons: RedactionReasons::empty().with(reason),
            usage: RedactionUsage::empty(),
        }
    }

    /// Creates a summary for a transaction that exhausted safe output capacity.
    ///
    /// # Returns
    ///
    /// An exhausted summary with the output-limit reason and empty accounting.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn exhausted() -> Self {
        Self {
            redaction_disabled: false,
            completion: RedactionCompletion::Exhausted,
            reasons: RedactionReasons::empty().with(RedactionReason::OutputLimitReached),
            usage: RedactionUsage::empty(),
        }
    }

    /// Returns completion state.
    ///
    /// # Returns
    ///
    /// The final completion state of the safe representation.
    #[must_use]
    #[inline(always)]
    pub const fn completion(self) -> RedactionCompletion {
        self.completion
    }

    /// Returns whether redaction was globally disabled for this operation.
    ///
    /// # Returns
    ///
    /// True when this operation intentionally bypassed redaction.
    #[must_use]
    #[inline(always)]
    pub const fn is_redaction_disabled(self) -> bool {
        self.redaction_disabled
    }

    /// Returns accumulated reasons.
    ///
    /// # Returns
    ///
    /// All machine-readable causes retained by the operation.
    #[must_use]
    #[inline(always)]
    pub const fn reasons(self) -> RedactionReasons {
        self.reasons
    }

    /// Returns resource use measured by the operation that produced this
    /// summary.
    ///
    /// # Returns
    ///
    /// The resource measurements associated with this operation.
    #[must_use]
    #[inline(always)]
    pub const fn usage(self) -> RedactionUsage {
        self.usage
    }
}
