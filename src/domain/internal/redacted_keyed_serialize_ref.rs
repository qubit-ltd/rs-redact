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
use super::redact_serialize_scope::RedactSerializeScope;
use super::redacted_level_serialize_ref::RedactedLevelSerializeRef;
use crate::RedactionPolicy;
use crate::policy::ResolvedField;

/// Defers serialization of one borrowed value until its sibling key is
/// classified.
///
/// The adapter retains the value, key, and policy by reference. Serialization
/// applies the key's resolved sensitivity while using the shared resource
/// scope; disabled policies and pass-through keys serialize the value directly.
#[doc(hidden)]
pub struct RedactedKeyedSerializeRef<'value, 'key, 'policy, T: ?Sized, K: ?Sized> {
    /// Source value serialized under the sensitivity resolved from `key`.
    value: &'value T,
    /// Runtime sibling key converted to a string when serialization begins.
    key: &'key K,
    /// Policy supplying key classification, masking, and resource limits.
    policy: &'policy RedactionPolicy,
}

impl<'value, 'key, 'policy, T: ?Sized, K: ?Sized> RedactedKeyedSerializeRef<'value, 'key, 'policy, T, K> {
    /// Retains a value, sibling key, and policy for later serialization.
    ///
    /// This constructor does not inspect or serialize the value. The key must
    /// be convertible to a string when the adapter is serialized.
    ///
    /// # Parameters
    ///
    /// - `value`: Source value borrowed for the adapter's lifetime.
    /// - `key`: Runtime sibling key used to resolve the value's sensitivity.
    /// - `policy`: Immutable policy used for classification and resource
    ///   limits.
    ///
    /// # Returns
    ///
    /// An adapter borrowing all three inputs without performing serialization.
    #[must_use]
    #[inline(always)]
    pub fn new(value: &'value T, key: &'key K, policy: &'policy RedactionPolicy) -> Self {
        Self { value, key, policy }
    }
}

impl<T, K> Serialize for RedactedKeyedSerializeRef<'_, '_, '_, T, K>
where
    T: ?Sized + RedactLevelSerialize + Serialize,
    K: ?Sized + AsRef<str>,
{
    /// Runs this borrowed adapter under the shared policy and resource scope.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Destination serializer defining the success and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted representation.
    ///
    /// # Returns
    ///
    /// The destination result after key classification and value serialization.
    ///
    /// # Errors
    ///
    /// Propagates admission failures and errors from the downstream serializer.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let _scope = RedactSerializeScope::new(self.policy);
        let key = self.key.as_ref();
        super::redact_serialize_scope::check_key_bytes::<S::Error>(key)?;
        if self.policy.is_disabled() {
            return super::budget_serialize::BudgetSerialize::new(self.value).serialize(serializer);
        }
        match super::resolve_keyed_field(self.policy, key) {
            ResolvedField::Sensitive { sensitivity } => {
                RedactedLevelSerializeRef::new(self.value, self.policy, sensitivity).serialize(serializer)
            }
            ResolvedField::PassThrough => {
                super::budget_serialize::BudgetSerialize::new(self.value).serialize(serializer)
            }
        }
    }
}
