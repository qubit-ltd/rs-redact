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
use serde::ser::Error as SerdeError;
use serde::ser::SerializeSeq;

use super::redact_serialize::RedactSerialize;
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::current_policy;
use super::redact_serialize_scope::serialize_payload;
use super::redact_serialize_scope::serialize_structured;
use super::redact_serialize_source::RedactSerializeSource;
use super::redacted_serialize_ref::RedactedSerializeRef;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Borrows a vector for structured redacted field traversal.
///
/// # Type Parameters
///
/// * `'a`: The source borrow lifetime.
/// * `T`: The nested source type.
pub struct VecProjection<'a, T>(
    /// The elements borrowed for this traversal.
    &'a [T],
);

impl<T> RedactSerializeSource for Vec<T> {
    /// A projection borrowing the source container.
    type RedactedFields<'a>
        = VecProjection<'a, T>
    where
        Self: 'a;

    /// Borrows the source; the caller must establish a serialization scope.
    #[inline(always)]
    fn redacted_fields<'a>(&'a self, _policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        VecProjection(self)
    }
}

impl<'value, T> Serialize for VecProjection<'value, T>
where
    T: RedactSerialize,
{
    /// Serializes the container within the current redaction scope.
    ///
    /// # Type Parameters
    ///
    /// * `S`: The destination serializer.
    ///
    /// # Parameters
    ///
    /// * `serializer`: The destination for the redacted representation.
    ///
    /// # Returns
    ///
    /// The serializer's output after applying the active policy and budgets.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when no redaction scope is active, or
    /// propagates errors from the destination serializer.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let policy_owner =
            current_policy().ok_or_else(|| S::Error::custom("serialization requires an active redaction scope"))?;
        let policy = policy_owner.as_ref();
        let Self(values) = self;
        serialize_structured(serializer, policy, |serializer| {
            if !admit_collection_items(values.len()) {
                return serialize_payload(serializer, policy.masking().mask_opaque(Sensitivity::Secret));
            }
            let mut sequence = serializer.serialize_seq(Some(values.len()))?;
            for value in *values {
                sequence.serialize_element(&RedactedSerializeRef::new(value, policy))?;
            }
            sequence.end()
        })
    }
}
