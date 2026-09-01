// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed adapter for values classified by a sibling policy key.

use serde::Serialize;
use serde::Serializer;

use super::redact_level_serialize::RedactLevelSerialize;
use super::redacted_level_serialize_ref::RedactedLevelSerializeRef;
use crate::RedactionPolicy;
use crate::policy::ResolvedField;

/// Borrowed serializer adapter for one keyed value.
#[doc(hidden)]
pub struct RedactedKeyedSerializeRef<'value, 'key, 'policy, T: ?Sized, K: ?Sized> {
    /// Borrowed source value.
    value: &'value T,
    /// Runtime key used to classify the source value.
    key: &'key K,
    /// Policy used to classify the key and mask the value.
    policy: &'policy RedactionPolicy,
}

impl<'value, 'key, 'policy, T: ?Sized, K: ?Sized>
    RedactedKeyedSerializeRef<'value, 'key, 'policy, T, K>
{
    /// Creates a policy-carrying borrowed keyed-value adapter.
    #[must_use]
    pub fn new(value: &'value T, key: &'key K, policy: &'policy RedactionPolicy) -> Self {
        Self { value, key, policy }
    }
}

impl<T, K> Serialize for RedactedKeyedSerializeRef<'_, '_, '_, T, K>
where
    T: ?Sized + RedactLevelSerialize + Serialize,
    K: ?Sized + AsRef<str>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.policy.is_disabled() {
            return self.value.serialize(serializer);
        }
        match super::resolve_keyed_field(self.policy, self.key.as_ref()) {
            ResolvedField::Sensitive { sensitivity } => {
                RedactedLevelSerializeRef::new(self.value, self.policy, sensitivity)
                    .serialize(serializer)
            }
            ResolvedField::PassThrough => self.value.serialize(serializer),
        }
    }
}
