// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Explainable borrowed results from field-policy classification.

use super::AllowRule;
use super::FieldMatchKind;
use super::SensitiveFieldRule;
use super::Sensitivity;

/// Explains why a field is sensitive, allowed, or unknown to a policy.
///
/// Matched rules borrow canonical field names from the immutable policy, so
/// callers can inspect classification without cloning rule metadata.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of canonical field names borrowed from the policy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClassification<'a> {
    /// A sensitive rule classified the field.
    Sensitive {
        /// Borrowed configured rule that supplied the sensitivity.
        rule: SensitiveFieldRule<'a>,
        /// The canonical input candidate that matched this rule.
        match_kind: FieldMatchKind,
    },
    /// An allow rule took precedence over sensitivity at the same candidate.
    Allowed {
        /// Borrowed configured rule that allowed the field.
        rule: AllowRule<'a>,
        /// The canonical input candidate that matched this rule.
        match_kind: FieldMatchKind,
    },
    /// No configured rule classified the field.
    Unknown,
}

impl<'a> FieldClassification<'a> {
    /// Returns the configured sensitivity when the field is sensitive.
    ///
    /// # Returns
    ///
    /// `Some(level)` for [`Self::Sensitive`], or `None` for allowed and unknown
    /// fields.
    #[must_use]
    pub const fn sensitivity(self) -> Option<Sensitivity> {
        match self {
            Self::Sensitive { rule, .. } => Some(rule.sensitivity()),
            Self::Allowed { .. } | Self::Unknown => None,
        }
    }

    /// Returns the canonical configured field that matched.
    ///
    /// # Returns
    ///
    /// A field name borrowed from the policy for sensitive and allowed
    /// classifications, or `None` for [`Self::Unknown`].
    #[must_use]
    pub const fn matched_field(self) -> Option<&'a str> {
        match self {
            Self::Sensitive { rule, .. } => Some(rule.field()),
            Self::Allowed { rule, .. } => Some(rule.field()),
            Self::Unknown => None,
        }
    }

    /// Returns the canonical input candidate that matched the configured rule.
    ///
    /// # Returns
    ///
    /// The exact input or a semantic token suffix for sensitive and allowed
    /// classifications, or `None` for [`Self::Unknown`].
    #[must_use]
    pub const fn match_kind(self) -> Option<FieldMatchKind> {
        match self {
            Self::Sensitive { match_kind, .. } | Self::Allowed { match_kind, .. } => {
                Some(match_kind)
            }
            Self::Unknown => None,
        }
    }

    /// Reports whether an allow rule classified the field.
    ///
    /// # Returns
    ///
    /// `true` only for [`Self::Allowed`].
    #[inline(always)]
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Reports whether no configured rule classified the field.
    ///
    /// # Returns
    ///
    /// `true` only for [`Self::Unknown`].
    #[inline(always)]
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::FieldClassification;

    #[test]
    fn unknown_predicates_are_mutually_exclusive() {
        let classification = FieldClassification::Unknown;

        assert!(!classification.is_allowed());
        assert!(classification.is_unknown());
    }
}
