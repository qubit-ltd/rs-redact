// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Borrowed redaction projections for vectors.

use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeSeq;

use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::current_policy;
use super::redact_serialize_scope::serialize_structured;
use super::redact_serialize_source::RedactSerializeSource;
use super::redacted_projection_ref::RedactedProjectionRef;
use crate::RedactionPolicy;
use crate::Sensitivity;

pub struct VecProjection<'a, T>(&'a Vec<T>);

impl<T> RedactSerializeSource for Vec<T> {
    type RedactedFields<'a>
        = VecProjection<'a, T>
    where
        Self: 'a;

    fn redacted_fields<'a>(&'a self, _policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
        VecProjection(self)
    }
}

impl<T: RedactSerializeSource> Serialize for VecProjection<'_, T>
where
    for<'a> T::RedactedFields<'a>: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let policy = current_policy().expect("active scope");
        serialize_structured(serializer, policy, |serializer| {
            if !admit_collection_items(self.0.len()) {
                return super::redact_serialize_scope::serialize_payload(
                    serializer,
                    policy.masking().mask_opaque(Sensitivity::Secret),
                );
            }
            let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
            for value in self.0 {
                sequence.serialize_element(&RedactedProjectionRef::new(value, policy))?;
            }
            sequence.end()
        })
    }
}
