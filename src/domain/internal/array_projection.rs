// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Borrowed redaction projection for fixed arrays.

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as SerdeError;
use serde::ser::SerializeSeq;

use crate::RedactionPolicy;
use crate::Sensitivity;

use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::current_policy;
use super::redact_serialize_scope::serialize_payload;
use super::redact_serialize_scope::serialize_structured;
use super::redact_serialize_source::RedactSerializeSource;
use super::redacted_projection_ref::RedactedProjectionRef;

/// Lazily serializes each borrowed array element through its redaction projection.
pub struct ArrayProjection<'value, T, const N: usize>(&'value [T; N]);

impl<T, const N: usize> RedactSerializeSource for [T; N] {
    type RedactedFields<'a>
        = ArrayProjection<'a, T, N>
    where
        Self: 'a;

    fn redacted_fields<'a>(&'a self, _policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        ArrayProjection(self)
    }
}

impl<'value, T, const N: usize> Serialize for ArrayProjection<'value, T, N>
where
    T: RedactSerializeSource + 'value,
    T::RedactedFields<'value>: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let policy_owner = current_policy()
            .ok_or_else(|| S::Error::custom("serialization requires an active redaction scope"))?;
        let policy = policy_owner.as_ref();
        let Self(values) = self;
        serialize_structured(serializer, policy, |serializer| {
            if !admit_collection_items(N) {
                return serialize_payload(
                    serializer,
                    policy.masking().mask_opaque(Sensitivity::Secret).as_ref(),
                );
            }
            let mut sequence = serializer.serialize_seq(Some(N))?;
            for value in *values {
                sequence.serialize_element(&RedactedProjectionRef::new(value, policy))?;
            }
            sequence.end()
        })
    }
}
