// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed adapter for maps with explicitly sensitive keys.

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
    /// Optional sensitivity applied uniformly to serialized values.
    value_level: Option<crate::Sensitivity>,
}

impl<'value, 'policy, T: ?Sized> RedactedMapKeySerializeRef<'value, 'policy, T> {
    /// Creates a map-key redaction adapter.
    #[must_use]
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

impl<T: ?Sized + RedactMapKeySerialize> serde::Serialize for RedactedMapKeySerializeRef<'_, '_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_structured(serializer, self.policy, |serializer| {
            self.value
                .serialize_redacted_map_keys(serializer, self.policy, self.level, self.value_level)
        })
    }
}
