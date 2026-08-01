// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Typed results of field-sensitive scalar redaction.

use std::borrow::Cow;

use crate::{LogSafeText, RedactedText, Sensitivity};

/// Explains whether a field value was masked or intentionally passed through.
#[must_use]
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

/// Reason a field value was retained without masking.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PassThroughReason {
    /// An application allow rule permitted the field.
    Allowed,
    /// No rule classified the field and the fallback is pass-through.
    Unknown,
}

impl<'a> FieldRedaction<'a> {
    /// Returns the processed value as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Masked { value, .. } => value.as_str(),
            Self::PassedThrough { value, .. } => value,
        }
    }

    /// Returns `true` when the value was masked.
    #[inline]
    pub const fn is_masked(&self) -> bool {
        matches!(self, Self::Masked { .. })
    }

    /// Returns the masking sensitivity, or `None` for pass-through values.
    #[inline]
    pub const fn sensitivity(&self) -> Option<Sensitivity> {
        match self {
            Self::Masked { sensitivity, .. } => Some(*sensitivity),
            Self::PassedThrough { .. } => None,
        }
    }

    /// Returns the pass-through reason, or `None` for masked values.
    #[inline]
    pub const fn pass_through_reason(&self) -> Option<PassThroughReason> {
        match self {
            Self::Masked { .. } => None,
            Self::PassedThrough { reason, .. } => Some(*reason),
        }
    }

    /// Converts the processed value into an owned string.
    #[inline]
    pub fn into_owned(self) -> String {
        match self {
            Self::Masked { value, .. } => value.into_owned(),
            Self::PassedThrough { value, .. } => value.to_owned(),
        }
    }

    /// Escapes the processed value for a plain-text log boundary.
    #[inline]
    pub fn escape_for_log(self) -> LogSafeText<'a> {
        match self {
            Self::Masked { value, .. } => value.escape_for_log(),
            Self::PassedThrough { value, .. } => {
                RedactedText::new(Cow::Borrowed(value)).escape_for_log()
            }
        }
    }
}
