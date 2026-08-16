// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Typed results of field-sensitive scalar redaction.

use std::borrow::Cow;

use crate::model::PassThroughReason;
use crate::model::Sensitivity;
use crate::output::LogSafeText;
use crate::output::RedactedText;

/// Explains whether a field value was masked or intentionally passed through.
///
/// [`std::fmt::Debug`] remains available for inspecting the policy result
/// during debugging. Plain-text log sinks should consume
/// [`Self::escape_for_log`] instead of formatting this enum directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldRedaction<'a> {
    /// The policy masked the value at the reported sensitivity.
    Masked {
        /// The typed masked value.
        value: RedactedText<'a>,
        /// Sensitivity used to select the mask.
        sensitivity: Sensitivity,
    },
    /// The policy intentionally retained the original value.
    PassedThrough {
        /// The original value borrowed from the caller.
        value: &'a str,
        /// Why the policy retained the value.
        reason: PassThroughReason,
    },
}

impl<'a> FieldRedaction<'a> {
    /// Returns the processed value as a string slice.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Masked { value, .. } => value.as_str(),
            Self::PassedThrough { value, .. } => value,
        }
    }

    /// Returns `true` when the value was masked.
    #[must_use]
    #[inline]
    pub const fn is_masked(&self) -> bool {
        matches!(self, Self::Masked { .. })
    }

    /// Returns the masking sensitivity, or `None` for pass-through values.
    #[must_use]
    #[inline]
    pub const fn sensitivity(&self) -> Option<Sensitivity> {
        match self {
            Self::Masked { sensitivity, .. } => Some(*sensitivity),
            Self::PassedThrough { .. } => None,
        }
    }

    /// Returns the pass-through reason, or `None` for masked values.
    #[must_use]
    #[inline]
    pub const fn pass_through_reason(&self) -> Option<PassThroughReason> {
        match self {
            Self::Masked { .. } => None,
            Self::PassedThrough { reason, .. } => Some(*reason),
        }
    }

    /// Converts the processed value into an owned string.
    #[must_use]
    #[inline]
    pub fn into_owned(self) -> String {
        match self {
            Self::Masked { value, .. } => value.into_owned(),
            Self::PassedThrough { value, .. } => value.to_owned(),
        }
    }

    /// Escapes the processed value for a plain-text log boundary.
    #[inline]
    #[must_use]
    pub fn escape_for_log(self) -> LogSafeText<'a> {
        match self {
            Self::Masked { value, .. } => value.escape_for_log(),
            Self::PassedThrough { value, .. } => {
                RedactedText::new(Cow::Borrowed(value)).escape_for_log()
            }
        }
    }
}
