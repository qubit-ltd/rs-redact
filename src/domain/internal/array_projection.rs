// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Borrowed redaction projection for fixed arrays.

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as SerdeError;
use serde::ser::SerializeTuple;

use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::current_policy;
use super::redact_serialize_scope::serialize_payload;
use super::redact_serialize_scope::serialize_structured;
use super::redact_serialize_source::RedactSerializeSource;
use super::redacted_projection_ref::RedactedProjectionRef;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Lazily serializes each borrowed array element through its redaction
/// projection, preserving the fixed-array tuple event when admitted.
///
/// The projection borrows the array and does not retain a policy. Serialization
/// obtains the active policy and shared budgets from the current redaction
/// scope.
pub struct ArrayProjection<'value, T, const N: usize>(&'value [T; N]);

impl<T, const N: usize> RedactSerializeSource for [T; N] {
    /// A borrowed projection that serializes the array under the active scope.
    type RedactedFields<'a>
        = ArrayProjection<'a, T, N>
    where
        Self: 'a;

    /// Borrows the array without retaining the supplied policy.
    ///
    /// The caller must establish an active redaction scope before
    /// serialization; serialization obtains its policy and shared budgets
    /// from that scope.
    fn redacted_fields<'a>(&'a self, _policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        ArrayProjection(self)
    }
}

impl<'value, T, const N: usize> Serialize for ArrayProjection<'value, T, N>
where
    T: RedactSerializeSource + 'value,
    T::RedactedFields<'value>: Serialize,
{
    /// Serializes admitted elements as a fixed-length tuple of redacted values.
    ///
    /// # Parameters
    ///
    /// * `serializer` - Serializer receiving the tuple or scalar replacement.
    ///
    /// # Returns
    ///
    /// The serializer's result for the tuple, or for a Secret scalar
    /// replacement when collection admission is denied.
    ///
    /// # Errors
    ///
    /// Returns a value-free error if there is no active redaction scope,
    /// including for an empty array. Errors reported by the serializer
    /// while writing either the tuple or its Secret scalar replacement are
    /// propagated. Denial of the collection budget is represented by
    /// serializing a Secret scalar replacement and does not itself
    /// guarantee an error.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let policy_owner =
            current_policy().ok_or_else(|| S::Error::custom("serialization requires an active redaction scope"))?;
        let policy = policy_owner.as_ref();
        let Self(values) = self;
        serialize_structured(serializer, policy, |serializer| {
            if !admit_collection_items(N) {
                return serialize_payload(serializer, policy.masking().mask_opaque(Sensitivity::Secret));
            }
            let mut tuple = serializer.serialize_tuple(N)?;
            for value in *values {
                tuple.serialize_element(&RedactedProjectionRef::new(value, policy))?;
            }
            tuple.end()
        })
    }
}
