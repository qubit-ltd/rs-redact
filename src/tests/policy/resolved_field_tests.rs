// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Monotone combination of internal field classification decisions.

use crate::Sensitivity;
use crate::policy::ResolvedField;

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
