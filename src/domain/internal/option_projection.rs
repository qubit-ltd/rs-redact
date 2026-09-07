// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed redaction projections for optional nested values.

use serde::Serialize;
use serde::Serializer;

use super::redact_borrowed_serialize::RedactBorrowedSerialize;
use super::redact_serialize_scope::RedactSerializeScope;
use super::redact_serialize_scope::current_policy;
use super::redact_serialize_source::RedactSerializeSource;
use super::redacted_borrowed_ref::RedactedBorrowedRef;
use crate::RedactionPolicy;

/// Borrows an optional container for structured redacted field traversal.
///
/// # Type Parameters
///
/// - `'a`: Actual source-container borrow, retained by child projections.
/// - `T`: Child type whose redacted projection is checked when serialized.
pub struct OptionProjection<'a, T>(
    /// Source container borrowed for the projection's lifetime.
    &'a Option<T>,
);

impl<T> RedactSerializeSource for Option<T> {
    /// Borrowed container projection; child capabilities are checked at
    /// serialization.
    type RedactedFields<'a>
        = OptionProjection<'a, T>
    where
        Self: 'a;

    /// Borrows the container without reading or cloning its child values.
    ///
    /// # Parameters
    ///
    /// - `_policy`: Snapshot applied by the enclosing serialization scope.
    ///
    /// # Returns
    ///
    /// A projection borrowing this optional container without visiting its
    /// child.
    ///
    /// # Type Parameters
    ///
    /// - `'a`: Borrow of the source container retained by the projection.
    #[inline(always)]
    fn redacted_fields<'a>(&'a self, _policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        OptionProjection(self)
    }
}

impl<'value, T> Serialize for OptionProjection<'value, T>
where
    &'value T: RedactBorrowedSerialize,
{
    /// Serializes children under the active snapshot and shared admission
    /// scope.
    ///
    /// # Errors
    ///
    /// Propagates child serializer failures and logical payload rejection.
    ///
    /// # Panics
    ///
    /// Panics if a nonempty projection is serialized without its required
    /// enclosing redaction scope; public views install that scope
    /// automatically.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Downstream serializer defining the result and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the optional child.
    ///
    /// # Returns
    ///
    /// The downstream result after the admitted representation is serialized.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            Some(value) => {
                let policy_owner = current_policy().expect("active scope");
                RedactedBorrowedRef::new(value, policy_owner.as_ref()).serialize(serializer)
            }
            None => serializer.serialize_none(),
        }
    }
}

impl<'value, T> RedactBorrowedSerialize for &'value Option<T>
where
    OptionProjection<'value, T>: Serialize,
{
    /// Serializes this container through its actual borrowed projection.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Destination serializer defining the result and error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted container.
    /// - `policy`: Snapshot installed for this borrowed container operation.
    ///
    /// # Returns
    ///
    /// The destination result after serializing the container projection.
    ///
    /// # Errors
    ///
    /// Propagates admission and downstream serialization failures.
    #[inline]
    fn serialize_borrowed<S>(self, serializer: S, policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let _scope = RedactSerializeScope::new(policy);
        self.redacted_fields(policy).serialize(serializer)
    }
}
