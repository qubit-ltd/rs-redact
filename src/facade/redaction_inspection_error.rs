// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fail-closed error returned when inspection cannot classify complete input.

use std::error::Error;
use std::fmt;

use super::RedactionReasons;
use super::RedactionUsage;

/// An inconclusive redaction inspection.
///
/// Callers must treat this error as potentially sensitive. The error exposes
/// only bounded accounting and machine-readable reasons; it never retains the
/// original input or a partial sensitivity result.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::RedactionReason;
/// use qubit_redact::Redactor;
///
/// let policy = RedactionPolicy::builder().limits(|limits| {
///     limits.max_input_bytes(0);
/// })?.build()?;
/// let error = Redactor::new(policy).inspect_field("id", "42").expect_err("no input allowed");
/// assert!(error.reasons().contains(RedactionReason::InputLimitReached));
/// # Ok::<(), qubit_redact::PolicyError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct RedactionInspectionError {
    /// Causes that prevented a conclusive classification.
    reasons: RedactionReasons,
    /// Resources consumed before inspection stopped.
    usage: RedactionUsage,
}

impl RedactionInspectionError {
    /// Creates an error from runtime-owned failure metadata.
    ///
    /// # Parameters
    ///
    /// - `reasons`: Causes preventing complete classification.
    /// - `usage`: Resources consumed before inspection stopped.
    ///
    /// # Returns
    ///
    /// A value-free error retaining reasons and usage, without partial
    /// sensitivity.
    #[inline(always)]
    pub(crate) const fn new(reasons: RedactionReasons, usage: RedactionUsage) -> Self {
        Self { reasons, usage }
    }

    /// Returns the machine-readable causes of incomplete inspection.
    ///
    /// # Returns
    ///
    /// The accumulated causes of inconclusive inspection.
    #[must_use]
    #[inline(always)]
    pub const fn reasons(&self) -> RedactionReasons {
        self.reasons
    }

    /// Returns resources consumed before the inspection became inconclusive.
    ///
    /// # Returns
    ///
    /// Resources consumed before complete classification became unavailable.
    #[must_use]
    #[inline(always)]
    pub const fn usage(&self) -> RedactionUsage {
        self.usage
    }
}

impl fmt::Display for RedactionInspectionError {
    /// Writes a safe diagnostic that never includes inspected input.
    ///
    /// # Parameters
    ///
    /// - `formatter`: Destination receiving a value-free diagnostic.
    ///
    /// # Returns
    ///
    /// Success after writing the inconclusive-inspection diagnostic.
    ///
    /// # Errors
    ///
    /// Propagates a destination formatting error.
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("redaction inspection was inconclusive")
    }
}

impl Error for RedactionInspectionError {}
