// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed adapter for structured JSON text redaction.

use super::redact_json_serialize::RedactJsonSerialize;

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
    pub fn new(value: &'value T, policy: &'policy crate::RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

#[cfg(feature = "json")]
impl<T: ?Sized + RedactJsonSerialize> serde::Serialize for RedactedJsonSerializeRef<'_, '_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value.serialize_redacted_json(serializer, self.policy)
    }
}
