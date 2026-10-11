// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared policy lookup for values classified by a runtime key.

use crate::RedactionPolicy;
use crate::policy::ResolvedField;

/// Resolves a runtime key through the active policy.
///
/// # Parameters
///
/// - `policy`: Active immutable policy snapshot.
/// - `key`: Raw runtime key normalized during resolution.
///
/// # Returns
///
/// The atomic sensitive or pass-through decision for the key.
#[must_use]
#[inline(always)]
pub(crate) fn resolve_keyed_field(policy: &RedactionPolicy, key: &str) -> ResolvedField {
    policy.resolve_field(key)
}

#[cfg(test)]
mod tests {
    use super::resolve_keyed_field;
    use crate::RedactionPolicy;
    use crate::Sensitivity;
    use crate::policy::ResolvedField;

    #[test]
    fn keyed_lookup_uses_policy_classification_for_runtime_keys() {
        let policy = RedactionPolicy::standard();
        assert!(matches!(
            resolve_keyed_field(&policy, "password"),
            ResolvedField::Sensitive {
                sensitivity: Sensitivity::Secret
            }
        ));
        assert!(matches!(
            resolve_keyed_field(&policy, "display_name"),
            ResolvedField::PassThrough
        ));
    }
}
