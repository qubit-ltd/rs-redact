// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed adapter for structured JSON text redaction.

use serde::Serialize;
use serde::Serializer;

use super::redact_json_serialize::RedactJsonSerialize;
use super::redact_serialize_scope::RedactSerializeScope;

/// Borrowed serializer adapter for one JSON text field.
#[doc(hidden)]
#[cfg(feature = "json")]
pub struct RedactedJsonSerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed JSON text value.
    value: &'value T,
    /// Policy used to redact parsed JSON.
    policy: &'policy crate::RedactionPolicy,
}

#[cfg(feature = "json")]
impl<'value, 'policy, T: ?Sized> RedactedJsonSerializeRef<'value, 'policy, T> {
    /// Creates a policy-carrying borrowed JSON adapter.
    #[must_use]
    #[inline(always)]
    pub fn new(value: &'value T, policy: &'policy crate::RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

#[cfg(feature = "json")]
impl<T: ?Sized + RedactJsonSerialize> Serialize for RedactedJsonSerializeRef<'_, '_, T> {
    /// Runs this borrowed adapter under the shared policy and resource scope.
    ///
    /// # Errors
    ///
    /// Propagates admission failures and errors from the downstream serializer.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let _scope = RedactSerializeScope::new(self.policy);
        self.value.serialize_redacted_json(serializer, self.policy)
    }
}
