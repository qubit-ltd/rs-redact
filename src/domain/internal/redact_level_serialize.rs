// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured serialization for values with an explicit sensitivity.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::BinaryHeap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::LinkedList;
use std::collections::VecDeque;
use std::fmt;
use std::fmt::Display;
use std::hash::Hash;
use std::rc::Rc;
use std::sync::Arc;

#[cfg(feature = "serde")]
use bigdecimal::BigDecimal;
use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;
use serde::ser::SerializeTuple;

use super::bounded_display_writer::BoundedDisplayWriter;
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::admit_input;
use super::redact_serialize_scope::remaining_input_bytes;
use super::redacted_level_serialize_ref::RedactedLevelSerializeRef;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Internal structured serialization capability for scalar level fields.
#[doc(hidden)]
pub trait RedactLevelSerialize {
    /// Serializes this value at the explicitly declared sensitivity.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

macro_rules! scalar_level_serialize {
    ($($type:ty),+ $(,)?) => {
        $(impl RedactLevelSerialize for $type {
            fn serialize_redacted_level<S>(
                &self,
                serializer: S,
                policy: &RedactionPolicy,
                level: Sensitivity,
            ) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if policy.is_disabled() {
                    serialize_disabled_display(self, serializer, policy)
                } else {
                    serialize_masked_display(self, serializer, policy, level)
                }
            }
        })+
    };
}

/// Serializes an admitted display value using the configured level mask.
fn serialize_masked_display<S, T>(
    value: &T,
    serializer: S,
    policy: &RedactionPolicy,
    level: Sensitivity,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Display + ?Sized,
{
    if matches!(level, Sensitivity::High | Sensitivity::Secret) {
        return serializer.serialize_str(policy.masking().mask_opaque(level));
    }
    let Some(raw) = format_admitted_display(value) else {
        return serializer.serialize_str(policy.masking().mask_opaque(Sensitivity::Secret));
    };
    serializer.serialize_str(policy.masking().mask(level, &raw).as_ref())
}

/// Serializes a raw disabled-mode scalar only after bounded input admission.
///
/// Values that exceed the remaining allowance serialize as the stable secret
/// opaque mask instead of invoking their ordinary serializer.
fn serialize_disabled_display<S, T>(value: &T, serializer: S, policy: &RedactionPolicy) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Display + Serialize + ?Sized,
{
    if format_admitted_display(value).is_none() {
        return serializer.serialize_str(policy.masking().mask_opaque(Sensitivity::Secret));
    }
    Serialize::serialize(value, serializer)
}

/// Formats and charges one scalar without allocating past the remaining input
/// allowance.
///
/// Returns the complete formatted value after charging it, or `None` when
/// formatting fails or the value exceeds the cumulative allowance.
#[must_use]
fn format_admitted_display<T>(value: &T) -> Option<String>
where
    T: Display + ?Sized,
{
    let mut writer = BoundedDisplayWriter::new(remaining_input_bytes());
    if fmt::write(&mut writer, format_args!("{value}")).is_err() {
        return None;
    }
    let raw = writer.finish();
    if !admit_input(raw.len()) {
        return None;
    }
    Some(raw)
}

scalar_level_serialize!(
    String, str, char, bool, i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize, f32, f64
);

#[cfg(feature = "serde")]
impl RedactLevelSerialize for BigDecimal {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if policy.is_disabled() {
            serialize_disabled_display(self, serializer, policy)
        } else {
            serialize_masked_display(self, serializer, policy, level)
        }
    }
}

impl<'a> RedactLevelSerialize for Cow<'a, str> {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if policy.is_disabled() {
            serialize_disabled_display(self, serializer, policy)
        } else {
            serialize_masked_display(self, serializer, policy, level)
        }
    }
}

impl RedactLevelSerialize for &str {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if policy.is_disabled() {
            serialize_disabled_display(self, serializer, policy)
        } else {
            serialize_masked_display(self, serializer, policy, level)
        }
    }
}

impl<T: RedactLevelSerialize> RedactLevelSerialize for Option<T> {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Some(value) => value.serialize_redacted_level(serializer, policy, level),
            None => serializer.serialize_none(),
        }
    }
}

impl<T: RedactLevelSerialize> RedactLevelSerialize for Vec<T> {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !admit_collection_items(self.len()) {
            return serializer.serialize_str(policy.masking().mask_opaque(Sensitivity::Secret).as_ref());
        }
        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for value in self {
            sequence.serialize_element(&RedactedLevelSerializeRef::new(value, policy, level))?;
        }
        sequence.end()
    }
}

macro_rules! sequence_level_serialize {
    ($($type:ident),+ $(,)?) => {
        $(impl<T: RedactLevelSerialize> RedactLevelSerialize for $type<T> {
            fn serialize_redacted_level<S>(&self, serializer: S, policy: &RedactionPolicy, level: Sensitivity) -> Result<S::Ok, S::Error>
            where S: Serializer {
                if !admit_collection_items(self.len()) {
                    return serializer.serialize_str(policy.masking().mask_opaque(Sensitivity::Secret).as_ref());
                }
                let mut sequence = serializer.serialize_seq(Some(self.len()))?;
                for value in self {
                    sequence.serialize_element(&RedactedLevelSerializeRef::new(value, policy, level))?;
                }
                sequence.end()
            }
        })+
    };
}

sequence_level_serialize!(VecDeque, LinkedList, BinaryHeap, BTreeSet, HashSet);

impl<T: RedactLevelSerialize + ?Sized> RedactLevelSerialize for Box<T> {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (**self).serialize_redacted_level(serializer, policy, level)
    }
}
impl<T: RedactLevelSerialize + ?Sized> RedactLevelSerialize for Rc<T> {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (**self).serialize_redacted_level(serializer, policy, level)
    }
}
impl<T: RedactLevelSerialize + ?Sized> RedactLevelSerialize for Arc<T> {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (**self).serialize_redacted_level(serializer, policy, level)
    }
}

impl<K: Serialize + Eq + Hash, V: RedactLevelSerialize> RedactLevelSerialize for HashMap<K, V> {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !admit_collection_items(self.len()) {
            return serializer.serialize_str(policy.masking().mask_opaque(Sensitivity::Secret).as_ref());
        }
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (key, value) in self {
            map.serialize_entry(key, &RedactedLevelSerializeRef::new(value, policy, level))?;
        }
        map.end()
    }
}
impl<K: Serialize + Ord, V: RedactLevelSerialize> RedactLevelSerialize for BTreeMap<K, V> {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !admit_collection_items(self.len()) {
            return serializer.serialize_str(policy.masking().mask_opaque(Sensitivity::Secret).as_ref());
        }
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (key, value) in self {
            map.serialize_entry(key, &RedactedLevelSerializeRef::new(value, policy, level))?;
        }
        map.end()
    }
}

impl<T: RedactLevelSerialize, const N: usize> RedactLevelSerialize for [T; N] {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &RedactionPolicy,
        level: Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !admit_collection_items(N) {
            return serializer.serialize_str(policy.masking().mask_opaque(Sensitivity::Secret).as_ref());
        }
        let mut sequence = serializer.serialize_seq(Some(N))?;
        for value in self {
            sequence.serialize_element(&RedactedLevelSerializeRef::new(value, policy, level))?;
        }
        sequence.end()
    }
}

macro_rules! tuple_level_serialize {
    ($count:expr; $($name:ident => $index:tt),+) => {
        impl<$($name: RedactLevelSerialize),+> RedactLevelSerialize for ($($name,)+) {
            fn serialize_redacted_level<S>(&self, serializer: S, policy: &RedactionPolicy, level: Sensitivity) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if !admit_collection_items($count) {
                    return serializer.serialize_str(
                        policy
                            .masking()
                            .mask_opaque(Sensitivity::Secret)
                            .as_ref(),
                    );
                }
                let mut tuple = serializer.serialize_tuple($count)?;
                $(tuple.serialize_element(&RedactedLevelSerializeRef::new(&self.$index, policy, level))?;)+
                tuple.end()
            }
        }
    };
}

tuple_level_serialize!(1; A => 0);
tuple_level_serialize!(2; A => 0, B => 1);
tuple_level_serialize!(3; A => 0, B => 1, C => 2);
tuple_level_serialize!(4; A => 0, B => 1, C => 2, D => 3);
tuple_level_serialize!(5; A => 0, B => 1, C => 2, D => 3, E => 4);
tuple_level_serialize!(6; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5);
tuple_level_serialize!(7; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6);
tuple_level_serialize!(8; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7);
tuple_level_serialize!(9; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8);
tuple_level_serialize!(10; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9);
tuple_level_serialize!(11; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10);
tuple_level_serialize!(12; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10, L => 11);

#[cfg(all(test, feature = "serde"))]
mod tests {
    use bigdecimal::BigDecimal;

    use crate::RedactionPolicy;
    use crate::Sensitivity;
    use crate::domain::internal::RedactSerializeScope;
    use crate::domain::internal::RedactedLevelSerializeRef;

    /// Verifies decimal leaves use the same cumulative bounded formatter as
    /// primitive structured values.
    #[test]
    fn test_big_decimal_level_values_share_the_input_budget() {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_input_bytes(4);
            })
            .expect("limits")
            .build()
            .expect("redaction policy");
        let values = vec![
            "123".parse::<BigDecimal>().expect("first decimal"),
            "45".parse::<BigDecimal>().expect("second decimal"),
        ];
        let _scope = RedactSerializeScope::new(&policy);

        let encoded = serde_json::to_value(RedactedLevelSerializeRef::new(&values, &policy, Sensitivity::Low))
            .expect("structured decimal serialization");

        assert_eq!(encoded[1], "<redacted>");
    }
}
