// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed adapter for maps with explicitly sensitive keys.

use serde::Serialize;
use serde::Serializer;

use super::RedactMapKeySerialize;
use super::redact_serialize_scope::serialize_structured;

/// Borrowed serializer adapter carrying policy and key sensitivity.
#[doc(hidden)]
pub struct RedactedMapKeySerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed map whose keys are classified explicitly.
    value: &'value T,
    /// Policy used to mask keys and optional values.
    policy: &'policy crate::RedactionPolicy,
    /// Sensitivity applied to every serialized key.
    level: crate::Sensitivity,
    /// `Some` applies one explicit sensitivity to every value; `None` uses
    /// each value's ordinary serializer under the shared budget.
    value_level: Option<crate::Sensitivity>,
}

impl<'value, 'policy, T: ?Sized> RedactedMapKeySerializeRef<'value, 'policy, T> {
    /// Creates a map-key redaction adapter.
    ///
    /// `Some(value_level)` also masks values at that level. `None` preserves
    /// their ordinary representation under the shared budget.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed source accessed only during serialization.
    /// - `policy`: Immutable policy borrowed independently of the source.
    /// - `level`: Explicit sensitivity applied to each key.
    /// - `value_level`: Some level masks value leaves; None preserves ordinary
    ///   budgeted values.
    ///
    /// # Returns
    ///
    /// A lazy adapter retaining the supplied source and policy references.
    #[must_use]
    #[inline(always)]
    pub fn new(
        value: &'value T,
        policy: &'policy crate::RedactionPolicy,
        level: crate::Sensitivity,
        value_level: Option<crate::Sensitivity>,
    ) -> Self {
        Self {
            value,
            policy,
            level,
            value_level,
        }
    }
}

impl<T: ?Sized + RedactMapKeySerialize> Serialize for RedactedMapKeySerializeRef<'_, '_, T> {
    /// Runs this borrowed adapter under the shared policy and resource scope.
    ///
    /// # Errors
    ///
    /// Propagates admission failures and errors from the downstream serializer.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the result and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_structured(serializer, self.policy, |serializer| {
            self.value
                .serialize_redacted_map_keys(serializer, self.policy, self.level, self.value_level)
        })
    }
}
