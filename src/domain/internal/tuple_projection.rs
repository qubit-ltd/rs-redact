// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Borrowed redaction projections for tuples.

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as SerdeError;
use serde::ser::SerializeTuple;

use crate::RedactionPolicy;
use crate::Sensitivity;

use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::current_policy;
use super::redact_serialize_scope::serialize_payload;
use super::redact_serialize_scope::serialize_structured;
use super::redact_serialize_source::RedactSerializeSource;
use super::redacted_projection_ref::RedactedProjectionRef;

/// Lazily serializes each borrowed tuple element through its redaction projection.
pub struct TupleProjection<'value, T: ?Sized>(&'value T);

macro_rules! tuple_projection {
    ($count:expr; $($name:ident => $index:tt),+) => {
        impl<$($name),+> RedactSerializeSource for ($($name,)+) {
            type RedactedFields<'a> = TupleProjection<'a, Self> where Self: 'a;

            fn redacted_fields<'a>(&'a self, _policy: &RedactionPolicy) -> Self::RedactedFields<'a> {
                TupleProjection(self)
            }
        }

        impl<'value, $($name),+> Serialize for TupleProjection<'value, ($($name,)+)>
        where
            $($name: RedactSerializeSource + 'value, <$name as RedactSerializeSource>::RedactedFields<'value>: Serialize,)+
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let policy_owner = current_policy()
                    .ok_or_else(|| S::Error::custom("serialization requires an active redaction scope"))?;
                let policy = policy_owner.as_ref();
                let values: &'value ($($name,)+) = self.0;
                serialize_structured(serializer, policy, |serializer| {
                    if !admit_collection_items($count) {
                        return serialize_payload(
                            serializer,
                            policy.masking().mask_opaque(Sensitivity::Secret).as_ref(),
                        );
                    }
                    let mut tuple = serializer.serialize_tuple($count)?;
                    $(tuple.serialize_element(&RedactedProjectionRef::new(&values.$index, policy))?;)+
                    tuple.end()
                })
            }
        }
    };
}

tuple_projection!(1; A => 0);
tuple_projection!(2; A => 0, B => 1);
tuple_projection!(3; A => 0, B => 1, C => 2);
tuple_projection!(4; A => 0, B => 1, C => 2, D => 3);
tuple_projection!(5; A => 0, B => 1, C => 2, D => 3, E => 4);
tuple_projection!(6; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5);
tuple_projection!(7; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6);
tuple_projection!(8; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7);
tuple_projection!(9; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8);
tuple_projection!(10; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9);
tuple_projection!(11; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10);
tuple_projection!(12; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10, L => 11);
