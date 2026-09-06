// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Generated structured serialization capability and containers.

use serde::Serializer;
use serde::ser::SerializeSeq;
use serde::ser::SerializeTuple;

use super::redact_serialize::RedactSerialize;
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::serialize_structured;
use super::redacted_serialize_ref::RedactedSerializeRef;

impl<T: RedactSerialize> RedactSerialize for Option<T> {
    fn serialize_redacted<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Some(value) => value.serialize_redacted(serializer, policy),
            None => serializer.serialize_none(),
        }
    }
}

impl<T: RedactSerialize> RedactSerialize for Vec<T> {
    fn serialize_redacted<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_structured(serializer, policy, |serializer| {
            if !admit_collection_items(self.len()) {
                return super::redact_serialize_scope::serialize_payload(
                    serializer,
                    policy.masking().mask_opaque(crate::Sensitivity::Secret),
                );
            }
            let mut sequence = serializer.serialize_seq(Some(self.len()))?;
            for value in self {
                sequence.serialize_element(&RedactedSerializeRef::new(value, policy))?;
            }
            sequence.end()
        })
    }
}

impl<T: RedactSerialize, const N: usize> RedactSerialize for [T; N] {
    fn serialize_redacted<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_structured(serializer, policy, |serializer| {
            if !admit_collection_items(N) {
                return super::redact_serialize_scope::serialize_payload(
                    serializer,
                    policy.masking().mask_opaque(crate::Sensitivity::Secret),
                );
            }
            let mut sequence = serializer.serialize_seq(Some(N))?;
            for value in self {
                sequence.serialize_element(&RedactedSerializeRef::new(value, policy))?;
            }
            sequence.end()
        })
    }
}

macro_rules! tuple_redact_serialize {
    ($count:expr; $($name:ident => $index:tt),+) => {
        impl<$($name: RedactSerialize),+> RedactSerialize for ($($name,)+) {
            fn serialize_redacted<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serialize_structured(serializer, policy, |serializer| {
                if !admit_collection_items($count) {
                    return super::redact_serialize_scope::serialize_payload(serializer,
                        policy
                            .masking()
                            .mask_opaque(crate::Sensitivity::Secret)
                            .as_ref(),
                    );
                }
                let mut tuple = serializer.serialize_tuple($count)?;
                $(tuple.serialize_element(&RedactedSerializeRef::new(&self.$index, policy))?;)+
                tuple.end()
                })
            }
        }
    };
}

tuple_redact_serialize!(1; A => 0);
tuple_redact_serialize!(2; A => 0, B => 1);
tuple_redact_serialize!(3; A => 0, B => 1, C => 2);
tuple_redact_serialize!(4; A => 0, B => 1, C => 2, D => 3);
tuple_redact_serialize!(5; A => 0, B => 1, C => 2, D => 3, E => 4);
tuple_redact_serialize!(6; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5);
tuple_redact_serialize!(7; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6);
tuple_redact_serialize!(8; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7);
tuple_redact_serialize!(9; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8);
tuple_redact_serialize!(10; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9);
tuple_redact_serialize!(11; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10);
tuple_redact_serialize!(12; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10, L => 11);
