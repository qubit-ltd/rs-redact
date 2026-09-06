// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Serde adapter for a derived borrowed redaction projection.

use super::redact_serialize_scope::RedactSerializeScope;
use super::redact_serialize_source::RedactSerializeSource;
use crate::RedactionPolicy;

/// Borrows a derived value and serializes its policy-carrying projection.
pub struct RedactedProjectionRef<'value, 'policy, T: ?Sized> {
    value: &'value T,
    policy: &'policy RedactionPolicy,
}

impl<'value, 'policy, T: ?Sized> RedactedProjectionRef<'value, 'policy, T> {
    /// Creates the adapter without reading the value.
    #[inline]
    pub const fn new(value: &'value T, policy: &'policy RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

impl<'value, 'policy, T: ?Sized + RedactSerializeSource> serde::Serialize
    for RedactedProjectionRef<'value, 'policy, T>
where
    T::RedactedFields<'value>: serde::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let _scope = RedactSerializeScope::new(self.policy);
        let projection = self.value.redacted_fields(self.policy);
        projection.serialize(serializer)
    }
}
