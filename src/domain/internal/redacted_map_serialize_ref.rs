// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed adapter for policy-classified structured maps.

use serde::Serialize;
use serde::Serializer;

use super::redact_map_serialize::RedactMapSerialize;
use super::redact_serialize_scope::serialize_structured;

/// Borrowed serializer adapter for one policy-classified map.
#[doc(hidden)]
pub struct RedactedMapSerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed map value.
    value: &'value T,
    /// Policy used to classify map keys.
    policy: &'policy crate::RedactionPolicy,
}

impl<'value, 'policy, T: ?Sized> RedactedMapSerializeRef<'value, 'policy, T> {
    /// Creates a policy-carrying borrowed map adapter.
    #[must_use]
    #[inline(always)]
    pub fn new(value: &'value T, policy: &'policy crate::RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

impl<T: ?Sized + RedactMapSerialize> Serialize for RedactedMapSerializeRef<'_, '_, T> {
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
            self.value.serialize_redacted_map(serializer, self.policy)
        })
    }
}
