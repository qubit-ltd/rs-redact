// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Atomic field-resolution result used by redaction executors.

use super::Sensitivity;

/// Final field decision selected atomically by one lookup.
///
/// A sensitive result contains only the final level. The owning redaction
/// policy supplies the single mask table used to render that level.
#[derive(Clone, Copy)]
pub(crate) enum ResolvedField {
    /// A field is sensitive at the final maximum level.
    Sensitive {
        /// Final sensitivity after applying application and floor rules.
        sensitivity: Sensitivity,
    },
    /// Neither the application rules nor an enabled floor require redaction.
    PassThrough,
}

impl ResolvedField {
    /// Combines this decision with a context enhancement without allowing the
    /// context to lower the existing protection level.
    #[must_use]
    #[cfg(any(feature = "http", test))]
    pub(crate) fn stronger(self, context: Self) -> Self {
        match (self, context) {
            (Self::Sensitive { sensitivity: base }, Self::Sensitive { sensitivity: context }) => Self::Sensitive {
                sensitivity: base.max(context),
            },
            (Self::Sensitive { sensitivity }, Self::PassThrough)
            | (Self::PassThrough, Self::Sensitive { sensitivity }) => Self::Sensitive { sensitivity },
            (Self::PassThrough, Self::PassThrough) => Self::PassThrough,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ResolvedField;
    use crate::Sensitivity;

    /// Verifies that a context decision cannot weaken a sensitive base
    /// decision.
    #[test]
    fn test_stronger_preserves_the_more_sensitive_base_decision() {
        let base = ResolvedField::Sensitive {
            sensitivity: Sensitivity::Secret,
        };
        let context = ResolvedField::Sensitive {
            sensitivity: Sensitivity::Low,
        };

        assert!(matches!(
            base.stronger(context),
            ResolvedField::Sensitive {
                sensitivity: Sensitivity::Secret
            }
        ));
    }

    /// Verifies that a context decision can strengthen a weaker base
    /// decision and that two pass-through decisions remain pass-through.
    #[test]
    fn test_stronger_accepts_context_enhancement_and_pass_through() {
        let base = ResolvedField::Sensitive {
            sensitivity: Sensitivity::Low,
        };
        let context = ResolvedField::Sensitive {
            sensitivity: Sensitivity::High,
        };

        assert!(matches!(
            base.stronger(context),
            ResolvedField::Sensitive {
                sensitivity: Sensitivity::High
            }
        ));
        assert!(matches!(
            ResolvedField::PassThrough.stronger(ResolvedField::PassThrough),
            ResolvedField::PassThrough
        ));
    }
}
