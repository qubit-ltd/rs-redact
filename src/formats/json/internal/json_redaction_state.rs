// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed policy and observation state for one admitted JSON tree.

use std::cell::Cell;

#[cfg(any(feature = "http", test))]
use super::JsonRedactionOutcome;
use super::JsonUnkeyedValuePolicy;
use super::RedactedValue;
use crate::MaskingPolicy;
use crate::RedactionRules;

/// Rules and observation state shared by one borrowed JSON serialization.
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

impl<'policy, 'marker> JsonRedactionState<'policy, 'marker> {
    /// Creates traversal state for one already-admitted JSON document.
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
    pub(crate) fn redact<'value, 'state>(
        &'state self,
        value: &'value serde_json::Value,
    ) -> RedactedValue<'value, 'policy, 'marker, 'state> {
        self.passed_unkeyed.set(false);
        RedactedValue::with_state(value, self)
    }

    /// Returns whether serialization passed through an unkeyed scalar.
    #[cfg(any(feature = "http", test))]
    pub(crate) fn outcome(&self) -> JsonRedactionOutcome {
        JsonRedactionOutcome::Complete {
            passed_unkeyed: self.passed_unkeyed.get(),
        }
    }

    /// Records an unkeyed scalar that policy allowed to remain visible.
    pub(crate) fn observe_unkeyed_passthrough(&self) {
        self.passed_unkeyed.set(true);
    }
}
