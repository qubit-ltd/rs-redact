// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed adapter for explicitly classified structured scalar values.

use serde::Serialize;
use serde::Serializer;

use super::redact_level_serialize::RedactLevelSerialize;
use super::redact_serialize_scope::serialize_structured;

/// Borrowed serializer adapter for one level field.
#[doc(hidden)]
pub struct RedactedLevelSerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed source value.
    value: &'value T,
    /// Policy used to mask the value.
    policy: &'policy crate::RedactionPolicy,
    /// Explicit sensitivity assigned to the value.
    level: crate::Sensitivity,
}

impl<'value, 'policy, T: ?Sized> RedactedLevelSerializeRef<'value, 'policy, T> {
    /// Creates a policy-carrying borrowed level adapter.
    #[must_use]
    #[inline(always)]
    pub fn new(value: &'value T, policy: &'policy crate::RedactionPolicy, level: crate::Sensitivity) -> Self {
        Self { value, policy, level }
    }
}

impl<T: ?Sized + RedactLevelSerialize> Serialize for RedactedLevelSerializeRef<'_, '_, T> {
    /// Runs this borrowed adapter under the shared policy and resource scope.
    ///
    /// # Errors
    ///
    /// Propagates admission failures and errors from the downstream serializer.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_structured(serializer, self.policy, |serializer| {
            self.value.serialize_redacted_level(serializer, self.policy, self.level)
        })
    }
}
