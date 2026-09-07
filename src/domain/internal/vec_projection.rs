// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed redaction projections for vectors.

use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeSeq;

use super::redact_borrowed_serialize::RedactBorrowedSerialize;
use super::redact_serialize_scope::RedactSerializeScope;
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::current_policy;
use super::redact_serialize_scope::serialize_structured;
use super::redact_serialize_source::RedactSerializeSource;
use super::redacted_borrowed_ref::RedactedBorrowedRef;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Borrows a vec container for structured redacted field traversal.
///
/// # Type Parameters
///
/// - `'a`: Actual source-container borrow, retained by child projections.
/// - `T`: Child type whose redacted projection is checked when serialized.
pub struct VecProjection<'a, T>(
    /// Source container borrowed for the projection's lifetime.
    &'a Vec<T>,
);

impl<T> RedactSerializeSource for Vec<T> {
    /// Borrowed container projection; child capabilities are checked at
    /// serialization.
    type RedactedFields<'a>
        = VecProjection<'a, T>
    where
        Self: 'a;

    /// Borrows the container without reading or cloning its child values.
    ///
    /// # Type Parameters
    ///
    /// - `'a`: Borrow of the source container retained by the projection.
    ///
    /// # Parameters
    ///
    /// - `_policy`: Snapshot applied by the enclosing serialization scope.
    ///
    /// # Returns
    ///
    /// A projection borrowing the vector without visiting its children.
    #[inline(always)]
    fn redacted_fields<'a>(&'a self, _policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        VecProjection(self)
    }
}

impl<'value, T> Serialize for VecProjection<'value, T>
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
    /// Panics if this projection is serialized without its required
    /// enclosing redaction scope; public views install that scope
    /// automatically.
    ///
    /// # Type Parameters
    ///
    /// - `S`: Destination serializer and its result/error types.
    ///
    /// # Parameters
    ///
    /// - `serializer`: Destination receiving the admitted child sequence.
    ///
    /// # Returns
    ///
    /// The destination result after visiting children under the actual source
    /// borrow.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let policy_owner = current_policy().expect("active scope");
        let policy = policy_owner.as_ref();
        serialize_structured(serializer, policy, |serializer| {
            if !admit_collection_items(self.0.len()) {
                return super::redact_serialize_scope::serialize_payload(
                    serializer,
                    policy.masking().mask_opaque(Sensitivity::Secret),
                );
            }
            let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
            for value in self.0 {
                sequence.serialize_element(&RedactedBorrowedRef::new(value, policy))?;
            }
            sequence.end()
        })
    }
}

impl<'value, T> RedactBorrowedSerialize for &'value Vec<T>
where
    VecProjection<'value, T>: Serialize,
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
