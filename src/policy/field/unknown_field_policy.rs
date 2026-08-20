// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Fallback behavior for fields without an explicit policy rule.

use super::Sensitivity;

/// Determines how a policy handles a field with no matching rule.
///
/// The default preserves compatibility by leaving unknown fields visible.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UnknownFieldPolicy {
    /// Leaves values visible when no explicit rule classifies their field.
    #[default]
    PassThrough,
    /// Applies the supplied sensitivity to every unclassified field.
    Redact(
        /// Sensitivity used as the fallback classification.
        Sensitivity,
    ),
}

impl UnknownFieldPolicy {
    /// Returns the sensitivity selected for an unclassified field.
    ///
    /// # Returns
    ///
    /// Some(level) when unknown fields must be redacted, or None when they
    /// must remain visible.
    #[must_use]
    #[inline(always)]
    pub const fn sensitivity(self) -> Option<Sensitivity> {
        match self {
            Self::PassThrough => None,
            Self::Redact(level) => Some(level),
        }
    }
}
