// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serde adapter for a derived borrowed redaction projection.

use serde::Serialize;
use serde::Serializer;

use super::redact_serialize_scope::RedactSerializeScope;
use super::redact_serialize_source::RedactSerializeSource;
use crate::RedactionPolicy;

/// Borrows a derived value and serializes its policy-carrying projection.
///
/// # Type Parameters
///
/// - `'value`: Actual borrow of the source retained by the projection.
/// - `'policy`: Lifetime of the independently borrowed policy.
/// - `T`: Source type whose projection capability is checked when serialized.
pub struct RedactedProjectionRef<'value, 'policy, T: ?Sized> {
    /// Source accessed only during serialization.
    value: &'value T,
    /// Policy borrowed for the shared Serde scope.
    policy: &'policy RedactionPolicy,
}

impl<'value, 'policy, T: ?Sized> RedactedProjectionRef<'value, 'policy, T> {
    /// Creates the adapter without reading the value.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed source accessed only during serialization.
    /// - `policy`: Immutable policy borrowed independently of the source.
    ///
    /// # Returns
    ///
    /// A lazy adapter retaining the supplied source and policy references.
    #[must_use]
    #[inline(always)]
    pub const fn new(value: &'value T, policy: &'policy RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

impl<'value, 'policy, T: ?Sized + RedactSerializeSource> Serialize for RedactedProjectionRef<'value, 'policy, T>
where
    T::RedactedFields<'value>: Serialize,
{
    /// Opens or joins one scope and serializes the generated projection once.
    ///
    /// # Errors
    ///
    /// Propagates admission or downstream projection serialization failures.
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
        let _scope = RedactSerializeScope::new(self.policy);
        let projection = self.value.redacted_fields(self.policy);
        projection.serialize(serializer)
    }
}
