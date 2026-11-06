// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed policy and observation state for one admitted JSON tree.

use std::cell::Cell;

use serde_json::Value;

#[cfg(any(feature = "http", test))]
use super::JsonRedactionOutcome;
use super::JsonUnkeyedValuePolicy;
use super::RedactedValue;
use crate::MaskingPolicy;
use crate::RedactionPolicy;
use crate::RedactionRules;

/// Rules and observation state shared by one borrowed JSON serialization.
///
/// Policy references remain borrowed for `'policy`, while an unkeyed marker may
/// have the independent lifetime `'marker`. Observation uses interior mutation;
/// this state is not shared across threads and starting a new traversal resets
/// it.
pub(crate) struct JsonRedactionState<'policy, 'marker> {
    /// Immutable base field rules.
    pub(crate) base_rules: &'policy RedactionRules,
    /// Context-specific field enhancements.
    pub(crate) context_rules: &'policy RedactionRules,
    /// Single mask table used for every sensitivity level.
    pub(crate) masking: &'policy MaskingPolicy,
    /// Handling for scalars without an object-key context.
    pub(crate) unkeyed: JsonUnkeyedValuePolicy<'marker>,
    /// Whether field rules are active for this operation.
    pub(crate) enabled: bool,
    /// Whether an unkeyed scalar remained visible during serialization.
    passed_unkeyed: Cell<bool>,
}

impl<'policy> JsonRedactionState<'policy, 'policy> {
    /// Creates traversal state from the policy used by ordinary JSON paths.
    ///
    /// # Parameters
    ///
    /// - `policy`: Borrowed rules, masks, and unkeyed-value handling. Base and
    ///   context rules both use this policy's rules.
    ///
    /// # Returns
    ///
    /// State borrowing `policy`, with no unkeyed pass-through observed yet.
    #[must_use]
    #[inline]
    pub(crate) fn from_policy(policy: &'policy RedactionPolicy) -> Self {
        let unkeyed = match policy.unkeyed_json_value_policy() {
            crate::UnkeyedJsonValuePolicy::PassThrough => JsonUnkeyedValuePolicy::PassThrough,
            crate::UnkeyedJsonValuePolicy::Redact => JsonUnkeyedValuePolicy::Redact {
                marker: policy.masking().mask_opaque(crate::Sensitivity::Secret),
            },
        };
        Self::new(
            policy.rules(),
            policy.rules(),
            policy.masking(),
            unkeyed,
            !policy.is_disabled(),
        )
    }
}

impl<'policy, 'marker> JsonRedactionState<'policy, 'marker> {
    /// Creates traversal state for one already-admitted JSON document.
    ///
    /// # Parameters
    ///
    /// - `base_rules`: Shared field rules borrowed for `'policy`.
    /// - `context_rules`: Context-specific enhancements borrowed for `'policy`.
    /// - `masking`: Mask table borrowed for `'policy`.
    /// - `unkeyed`: Scalar handling, including any marker borrowed for
    ///   `'marker`.
    /// - `enabled`: Whether serialization applies the field rules.
    ///
    /// # Returns
    ///
    /// State holding the supplied policy components without cloning them, with
    /// no unkeyed pass-through observed yet.
    #[must_use]
    #[inline]
    pub(crate) const fn new(
        base_rules: &'policy RedactionRules,
        context_rules: &'policy RedactionRules,
        masking: &'policy MaskingPolicy,
        unkeyed: JsonUnkeyedValuePolicy<'marker>,
        enabled: bool,
    ) -> Self {
        Self {
            base_rules,
            context_rules,
            masking,
            unkeyed,
            enabled,
            passed_unkeyed: Cell::new(false),
        }
    }

    /// Creates a borrowed serializer and resets the pass-through observation.
    ///
    /// # Parameters
    ///
    /// - `value`: JSON tree borrowed for `'value`; it is not cloned or
    ///   modified.
    ///
    /// # Returns
    ///
    /// A serializer borrowing both `value` and this state. Traversing it
    /// records any unkeyed pass-through in this state; creating it alone
    /// does not traverse.
    #[inline]
    pub(crate) fn redact<'value, 'state>(
        &'state self,
        value: &'value Value,
    ) -> RedactedValue<'value, 'policy, 'marker, 'state> {
        self.passed_unkeyed.set(false);
        RedactedValue::with_state(value, self)
    }

    /// Returns whether serialization passed through an unkeyed scalar.
    ///
    /// # Returns
    ///
    /// A snapshot of the observation since the last `redact` call, or since
    /// construction if no traversal has started. Reading it does not reset it.
    #[must_use]
    #[inline]
    #[cfg(any(feature = "http", test))]
    pub(crate) fn outcome(&self) -> JsonRedactionOutcome {
        JsonRedactionOutcome::Complete {
            passed_unkeyed: self.passed_unkeyed.get(),
        }
    }

    /// Records an unkeyed scalar that policy allowed to remain visible.
    #[inline]
    pub(crate) fn observe_unkeyed_passthrough(&self) {
        self.passed_unkeyed.set(true);
    }
}
