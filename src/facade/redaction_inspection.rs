// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Conclusive sensitivity metadata produced without rendering source values.

use super::RedactionUsage;
use crate::Sensitivity;

/// Highest sensitivity found by one complete, bounded inspection.
///
/// A successful value is conclusive under the selected policy. [`None`] from
/// [`Self::max_sensitivity`] means no inspected value was declared sensitive;
/// a disabled policy deliberately bypasses classification, as reported by
/// [`Self::is_redaction_disabled`]. It does not prove that source data is
/// inherently nonsensitive. Inconclusive traversal is returned as
/// [`crate::RedactionInspectionError`] instead of this type.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
/// use qubit_redact::Sensitivity;
///
/// let inspection = Redactor::strict()
///     .inspect_field("password", "raw-secret")
///     .expect("the scalar inspection is bounded and valid");
/// assert_eq!(inspection.max_sensitivity(), Some(Sensitivity::Secret));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionInspection {
    /// Whether policy evaluation was bypassed for this complete traversal.
    redaction_disabled: bool,
    /// Strongest sensitivity observed during the complete traversal.
    max_sensitivity: Option<Sensitivity>,
    /// Resource use excluding any output bytes, because inspection does not
    /// render.
    usage: RedactionUsage,
}

impl RedactionInspection {
    /// Creates a conclusive inspection from runtime-owned metadata.
    ///
    /// # Parameters
    ///
    /// - `redaction_disabled`: Whether the complete inspection intentionally
    ///   bypassed policy classification.
    /// - `max_sensitivity`: Some strongest observed level, or None when the
    ///   selected policy declared no value sensitive.
    /// - `usage`: Resource accounting with zero rendered output bytes.
    ///
    /// # Returns
    ///
    /// A conclusive inspection retaining the supplied metadata.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn new(
        redaction_disabled: bool,
        max_sensitivity: Option<Sensitivity>,
        usage: RedactionUsage,
    ) -> Self {
        Self {
            redaction_disabled,
            max_sensitivity,
            usage,
        }
    }

    /// Reports whether the complete traversal found sensitive data.
    ///
    /// # Returns
    ///
    /// True when the complete traversal found at least one sensitive value.
    #[must_use]
    #[inline(always)]
    pub const fn contains_sensitive(&self) -> bool {
        self.max_sensitivity.is_some()
    }

    /// Returns whether the selected policy disabled this inspection.
    ///
    /// # Returns
    ///
    /// True when policy classification was intentionally disabled for this
    /// inspection.
    #[must_use]
    #[inline(always)]
    pub const fn is_redaction_disabled(&self) -> bool {
        self.redaction_disabled
    }

    /// Returns the strongest sensitivity found by the complete traversal.
    ///
    /// # Returns
    ///
    /// `Some(level)` for declared sensitive data, or `None` when the selected
    /// policy declared none, including when classification was disabled.
    #[must_use]
    #[inline(always)]
    pub const fn max_sensitivity(&self) -> Option<Sensitivity> {
        self.max_sensitivity
    }

    /// Returns resources consumed while classifying the input.
    ///
    /// Output bytes are always zero because inspection never renders values.
    ///
    /// # Returns
    ///
    /// Resources consumed during complete classification, with zero output
    /// bytes.
    #[must_use]
    #[inline(always)]
    pub const fn usage(&self) -> RedactionUsage {
        self.usage
    }
}
