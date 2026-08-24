// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
// qubit-style: allow multiple-public-types
// qubit-style: allow all

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;

#[cfg(feature = "serde")]
use bigdecimal::BigDecimal;

mod serde {
    pub use ::serde::Serialize;
    pub use ::serde::Serializer;

    pub mod ser {
        pub use ::serde::ser::Error;
        pub use ::serde::ser::Impossible;
        pub use ::serde::ser::SerializeMap;
        pub use ::serde::ser::SerializeSeq;
        pub use ::serde::ser::SerializeStruct;
        pub use ::serde::ser::SerializeTuple;
    }
}

use self::serde::ser::Error as SerdeError;
use self::serde::ser::SerializeMap;
use self::serde::ser::SerializeSeq;
use self::serde::ser::SerializeTuple;

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct StructuredSerdeBudget {
    /// Limits copied from the active redaction policy.
    policy: crate::policy::RedactionLimits,
    /// Current structured traversal depth.
    depth: usize,
    /// Structural nodes admitted so far.
    nodes: usize,
    /// Collection items admitted so far.
    collection_items: usize,
    /// Input bytes admitted so far.
    input_bytes: usize,
}

thread_local! {
    static STRUCTURED_SERDE_BUDGET: RefCell<Option<StructuredSerdeBudget>> = const { RefCell::new(None) };
}

/// Hidden scope that shares structural Serde admission across nested derives.
#[doc(hidden)]
pub struct RedactSerializeScope {
    /// Budget restored when this nested scope ends.
    previous: Option<StructuredSerdeBudget>,
}

impl RedactSerializeScope {
    /// Starts one policy-scoped structured serialization budget.
    #[must_use]
    pub fn new(policy: &crate::RedactionPolicy) -> Self {
        let previous = STRUCTURED_SERDE_BUDGET.with(|slot| {
            slot.replace(Some(StructuredSerdeBudget {
                policy: *policy.limits(),
                depth: 0,
                nodes: 0,
                collection_items: 0,
                input_bytes: 0,
            }))
        });
        Self { previous }
    }
}

impl Drop for RedactSerializeScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        STRUCTURED_SERDE_BUDGET.with(|slot| {
            slot.replace(previous);
        });
    }
}

/// Admits one structured node and enters its depth scope.
#[allow(dead_code)]
fn admit_node() -> bool {
    STRUCTURED_SERDE_BUDGET.with(|slot| {
        let mut state = slot.borrow_mut();
        let Some(state) = state.as_mut() else {
            return true;
        };
        if state.policy.max_depth().is_some_and(|maximum| state.depth >= maximum)
            || state.policy.max_nodes().is_some_and(|maximum| state.nodes >= maximum)
        {
            return false;
        }
        state.depth += 1;
        state.nodes += 1;
        true
    })
}

/// Leaves the most recently admitted structured node.
#[allow(dead_code)]
fn leave_node() {
    STRUCTURED_SERDE_BUDGET.with(|slot| {
        if let Some(state) = slot.borrow_mut().as_mut() {
            state.depth = state.depth.saturating_sub(1);
        }
    });
}

/// Admits `count` additional collection items.
fn admit_collection_items(count: usize) -> bool {
    STRUCTURED_SERDE_BUDGET.with(|slot| {
        let mut state = slot.borrow_mut();
        let Some(state) = state.as_mut() else {
            return true;
        };
        let next = state.collection_items.saturating_add(count);
        if state
            .policy
            .max_collection_items()
            .is_some_and(|maximum| next > maximum)
        {
            return false;
        }
        state.collection_items = next;
        true
    })
}

/// Admits `bytes` additional source bytes.
#[allow(dead_code)]
fn admit_input(bytes: usize) -> bool {
    STRUCTURED_SERDE_BUDGET.with(|slot| {
        let mut state = slot.borrow_mut();
        let Some(state) = state.as_mut() else {
            return true;
        };
        let next = state.input_bytes.saturating_add(bytes);
        if next > state.policy.max_input_bytes() {
            return false;
        }
        state.input_bytes = next;
        true
    })
}

/// Returns the input bytes still available to the active structured serializer.
#[must_use]
fn remaining_input_bytes() -> usize {
    STRUCTURED_SERDE_BUDGET.with(|slot| {
        let state = slot.borrow();
        state.as_ref().map_or(usize::MAX, |state| {
            state.policy.max_input_bytes().saturating_sub(state.input_bytes)
        })
    })
}

/// Accumulates one display value without allocating past its input allowance.
struct BoundedDisplayWriter {
    /// Complete UTF-8 fragments accepted so far.
    output: String,
    /// Remaining byte allowance.
    remaining: usize,
}

impl BoundedDisplayWriter {
    /// Creates a writer limited to `remaining` UTF-8 bytes.
    #[must_use]
    fn new(remaining: usize) -> Self {
        Self {
            output: String::new(),
            remaining,
        }
    }

    /// Returns the complete formatted value after successful formatting.
    #[must_use]
    fn finish(self) -> String {
        self.output
    }
}

impl fmt::Write for BoundedDisplayWriter {
    /// Appends a complete fragment or stops formatting before exceeding the
    /// configured input allowance.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the complete fragment does not fit. No
    /// partial fragment is retained in that case.
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if value.len() > self.remaining {
            return Err(fmt::Error);
        }
        self.output.push_str(value);
        self.remaining -= value.len();
        Ok(())
    }
}

/// Runs one generated structured serializer under the shared budget.
#[doc(hidden)]
pub fn serialize_structured<S, F>(serializer: S, policy: &crate::RedactionPolicy, body: F) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    F: FnOnce(S) -> Result<S::Ok, S::Error>,
{
    if !admit_node() {
        return serializer.serialize_str(policy.masking().mask_opaque(crate::Sensitivity::Secret).as_ref());
    }
    let result = body(serializer);
    leave_node();
    result
}

/// Serializes a map-like newtype payload with an injected internal enum tag.
#[doc(hidden)]
pub fn serialize_internally_tagged<S, T>(
    serializer: S,
    enum_name: &'static str,
    variant_name: &'static str,
    tag: &'static str,
    tag_value: &'static str,
    value: &T,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: serde::Serialize + ?Sized,
{
    value.serialize(InternallyTaggedSerializer {
        serializer,
        enum_name,
        variant_name,
        tag,
        tag_value,
    })
}

struct InternallyTaggedSerializer<S> {
    /// Underlying serializer receiving the tagged map.
    serializer: S,
    /// Declared enum type name used in errors.
    enum_name: &'static str,
    /// Declared variant name used in errors.
    variant_name: &'static str,
    /// Internal tag field name.
    tag: &'static str,
    /// Internal tag field value.
    tag_value: &'static str,
}

/// Map adapter returned after injecting an internal enum tag.
struct InternallyTaggedMap<M> {
    /// Underlying serialized map.
    map: M,
}

impl<M: serde::ser::SerializeMap> serde::ser::SerializeMap for InternallyTaggedMap<M> {
    type Ok = M::Ok;
    type Error = M::Error;

    fn serialize_key<T: ?Sized + serde::Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.map.serialize_key(key)
    }

    fn serialize_value<T: ?Sized + serde::Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.map.serialize_value(value)
    }

    fn serialize_entry<K: ?Sized + serde::Serialize, V: ?Sized + serde::Serialize>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), Self::Error> {
        self.map.serialize_entry(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.map.end()
    }
}

impl<M: serde::ser::SerializeMap> serde::ser::SerializeStruct for InternallyTaggedMap<M> {
    type Ok = M::Ok;
    type Error = M::Error;

    fn serialize_field<T: ?Sized + serde::Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.map.serialize_entry(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.map.end()
    }
}

impl<S: serde::Serializer> serde::Serializer for InternallyTaggedSerializer<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = serde::ser::Impossible<S::Ok, S::Error>;
    type SerializeTuple = serde::ser::Impossible<S::Ok, S::Error>;
    type SerializeTupleStruct = serde::ser::Impossible<S::Ok, S::Error>;
    type SerializeTupleVariant = serde::ser::Impossible<S::Ok, S::Error>;
    type SerializeMap = InternallyTaggedMap<S::SerializeMap>;
    type SerializeStruct = InternallyTaggedMap<S::SerializeMap>;
    type SerializeStructVariant = serde::ser::Impossible<S::Ok, S::Error>;

    fn serialize_map(self, length: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        let mut map = self
            .serializer
            .serialize_map(length.map(|length| length.saturating_add(1)))?;
        map.serialize_entry(self.tag, self.tag_value)?;
        Ok(InternallyTaggedMap { map })
    }

    fn serialize_struct(self, _name: &'static str, length: usize) -> Result<Self::SerializeStruct, Self::Error> {
        self.serialize_map(Some(length))
    }

    fn serialize_bool(self, _value: bool) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_i8(self, _value: i8) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_i16(self, _value: i16) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_i32(self, _value: i32) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_i64(self, _value: i64) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_i128(self, _value: i128) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_u8(self, _value: u8) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_u16(self, _value: u16) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_u32(self, _value: u32) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_u64(self, _value: u64) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_u128(self, _value: u128) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_f32(self, _value: f32) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_f64(self, _value: f64) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_char(self, _value: char) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_str(self, _value: &str) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_some<T: ?Sized + serde::Serialize>(self, _value: &T) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_newtype_struct<T: ?Sized + serde::Serialize>(
        self,
        _name: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_newtype_variant<T: ?Sized + serde::Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_seq(self, _length: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.unsupported()
    }
    fn serialize_tuple(self, _length: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.unsupported()
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.unsupported()
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.unsupported()
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.unsupported()
    }
}

impl<S: serde::Serializer> InternallyTaggedSerializer<S> {
    /// Reports that internally tagged newtypes require a map-like payload.
    fn unsupported<T>(self) -> Result<T, S::Error> {
        Err(SerdeError::custom(format_args!(
            "cannot serialize internally tagged {} variant {} newtype from a non-map value",
            self.enum_name, self.variant_name,
        )))
    }
}

/// Internal structured serialization capability generated by the derive crate.
#[doc(hidden)]
pub trait RedactSerialize {
    /// Serializes this value through its generated redaction policy adapter.
    fn serialize_redacted<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}

/// Internal structured serialization capability for scalar level fields.
#[doc(hidden)]
pub trait RedactLevelSerialize {
    /// Serializes this value at the explicitly declared sensitivity.
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &crate::RedactionPolicy,
        level: crate::Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}

/// Borrowed serializer adapter for one level field.
#[doc(hidden)]
pub struct RedactedLevelSerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed source value.
    value: &'value T,
    /// Policy used to mask the value.
    policy: &'policy crate::RedactionPolicy,
    /// Explicit sensitivity assigned to the value.
    level: crate::Sensitivity,
}

impl<'value, 'policy, T: ?Sized> RedactedLevelSerializeRef<'value, 'policy, T> {
    /// Creates a policy-carrying borrowed level adapter.
    #[must_use]
    pub fn new(value: &'value T, policy: &'policy crate::RedactionPolicy, level: crate::Sensitivity) -> Self {
        Self { value, policy, level }
    }
}

impl<T: ?Sized + RedactLevelSerialize> serde::Serialize for RedactedLevelSerializeRef<'_, '_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value.serialize_redacted_level(serializer, self.policy, self.level)
    }
}

macro_rules! scalar_level_serialize {
    ($($type:ty),+ $(,)?) => {
        $(impl RedactLevelSerialize for $type {
            fn serialize_redacted_level<S>(
                &self,
                serializer: S,
                policy: &crate::RedactionPolicy,
                level: crate::Sensitivity,
            ) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
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
    policy: &crate::RedactionPolicy,
    level: crate::Sensitivity,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: std::fmt::Display + ?Sized,
{
    if matches!(level, crate::Sensitivity::High | crate::Sensitivity::Secret) {
        return serializer.serialize_str(policy.masking().mask_opaque(level));
    }
    let Some(raw) = format_admitted_display(value) else {
        return serializer.serialize_str(policy.masking().mask_opaque(crate::Sensitivity::Secret));
    };
    serializer.serialize_str(policy.masking().mask(level, &raw).as_ref())
}

/// Serializes a raw disabled-mode scalar only after bounded input admission.
///
/// Values that exceed the remaining allowance serialize as the stable secret
/// opaque mask instead of invoking their ordinary serializer.
fn serialize_disabled_display<S, T>(
    value: &T,
    serializer: S,
    policy: &crate::RedactionPolicy,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: std::fmt::Display + serde::Serialize + ?Sized,
{
    if format_admitted_display(value).is_none() {
        return serializer.serialize_str(policy.masking().mask_opaque(crate::Sensitivity::Secret));
    }
    serde::Serialize::serialize(value, serializer)
}

/// Formats and charges one scalar without allocating past the remaining input
/// allowance.
///
/// Returns the complete formatted value after charging it, or `None` when
/// formatting fails or the value exceeds the cumulative allowance.
#[must_use]
fn format_admitted_display<T>(value: &T) -> Option<String>
where
    T: std::fmt::Display + ?Sized,
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
        policy: &crate::RedactionPolicy,
        level: crate::Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
        policy: &crate::RedactionPolicy,
        level: crate::Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
        policy: &crate::RedactionPolicy,
        level: crate::Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
        policy: &crate::RedactionPolicy,
        level: crate::Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
        policy: &crate::RedactionPolicy,
        level: crate::Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if !admit_collection_items(self.len()) {
            return serializer.serialize_str(policy.masking().mask_opaque(crate::Sensitivity::Secret).as_ref());
        }
        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for value in self {
            sequence.serialize_element(&RedactedLevelSerializeRef::new(value, policy, level))?;
        }
        sequence.end()
    }
}

impl<T: RedactLevelSerialize, const N: usize> RedactLevelSerialize for [T; N] {
    fn serialize_redacted_level<S>(
        &self,
        serializer: S,
        policy: &crate::RedactionPolicy,
        level: crate::Sensitivity,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if !admit_collection_items(N) {
            return serializer.serialize_str(policy.masking().mask_opaque(crate::Sensitivity::Secret).as_ref());
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
            fn serialize_redacted_level<S>(&self, serializer: S, policy: &crate::RedactionPolicy, level: crate::Sensitivity) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if !admit_collection_items($count) {
                    return serializer.serialize_str(
                        policy
                            .masking()
                            .mask_opaque(crate::Sensitivity::Secret)
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

/// Borrowed serializer adapter that carries one immutable redaction policy.
#[doc(hidden)]
pub struct RedactedSerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed source value.
    value: &'value T,
    /// Policy used by generated serialization.
    policy: &'policy crate::RedactionPolicy,
}

impl<'value, 'policy, T: ?Sized> RedactedSerializeRef<'value, 'policy, T> {
    /// Creates a policy-carrying borrowed serializer adapter.
    #[must_use]
    pub fn new(value: &'value T, policy: &'policy crate::RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

impl<T: ?Sized + RedactSerialize> serde::Serialize for RedactedSerializeRef<'_, '_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value.serialize_redacted(serializer, self.policy)
    }
}

impl<T: RedactSerialize> RedactSerialize for Option<T> {
    fn serialize_redacted<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
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
        S: serde::Serializer,
    {
        if !admit_collection_items(self.len()) {
            return serializer.serialize_str(policy.masking().mask_opaque(crate::Sensitivity::Secret).as_ref());
        }
        let mut sequence = serializer.serialize_seq(Some(self.len()))?;
        for value in self {
            sequence.serialize_element(&RedactedSerializeRef::new(value, policy))?;
        }
        sequence.end()
    }
}

impl<T: RedactSerialize, const N: usize> RedactSerialize for [T; N] {
    fn serialize_redacted<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if !admit_collection_items(N) {
            return serializer.serialize_str(policy.masking().mask_opaque(crate::Sensitivity::Secret).as_ref());
        }
        let mut sequence = serializer.serialize_seq(Some(N))?;
        for value in self {
            sequence.serialize_element(&RedactedSerializeRef::new(value, policy))?;
        }
        sequence.end()
    }
}

/// Internal structured serialization capability for policy-classified maps.
#[doc(hidden)]
pub trait RedactMapSerialize {
    /// Serializes a map after classifying each value by its field key.
    fn serialize_redacted_map<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}

/// Borrowed serializer adapter for one policy-classified map.
#[doc(hidden)]
pub struct RedactedMapSerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed map value.
    value: &'value T,
    /// Policy used to classify map keys.
    policy: &'policy crate::RedactionPolicy,
}

impl<'value, 'policy, T: ?Sized> RedactedMapSerializeRef<'value, 'policy, T> {
    /// Creates a policy-carrying borrowed map adapter.
    #[must_use]
    pub fn new(value: &'value T, policy: &'policy crate::RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

impl<T: ?Sized + RedactMapSerialize> serde::Serialize for RedactedMapSerializeRef<'_, '_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value.serialize_redacted_map(serializer, self.policy)
    }
}

macro_rules! map_redact_serialize {
    ($map:ty) => {
        impl<K, V> RedactMapSerialize for $map
        where
            K: AsRef<str> + serde::Serialize,
            V: RedactLevelSerialize + serde::Serialize,
        {
            fn serialize_redacted_map<S>(
                &self,
                serializer: S,
                policy: &crate::RedactionPolicy,
            ) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if !admit_collection_items(self.len()) {
                    return serializer.serialize_str(policy.masking().mask_opaque(crate::Sensitivity::Secret).as_ref());
                }
                let mut map = serializer.serialize_map(Some(self.len()))?;
                for (key, value) in self {
                    let key_name = key.as_ref();
                    if !policy.is_disabled() {
                        if let Some(level) = policy.sensitivity_for(key_name) {
                            map.serialize_entry(key, &RedactedLevelSerializeRef::new(value, policy, level))?;
                            continue;
                        }
                    }
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }

        impl<K, V> RedactMapSerialize for Option<$map>
        where
            K: AsRef<str> + serde::Serialize,
            V: RedactLevelSerialize + serde::Serialize,
        {
            fn serialize_redacted_map<S>(
                &self,
                serializer: S,
                policy: &crate::RedactionPolicy,
            ) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                match self {
                    Some(value) => value.serialize_redacted_map(serializer, policy),
                    None => serializer.serialize_none(),
                }
            }
        }
    };
}

map_redact_serialize!(HashMap<K, V>);
map_redact_serialize!(BTreeMap<K, V>);

/// Internal structured serialization capability for JSON text fields.
#[doc(hidden)]
#[cfg(feature = "json")]
pub trait RedactJsonSerialize {
    /// Parses and serializes JSON text through structured redaction.
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer;
}

/// Borrowed serializer adapter for one JSON text field.
#[doc(hidden)]
#[cfg(feature = "json")]
pub struct RedactedJsonSerializeRef<'value, 'policy, T: ?Sized> {
    /// Borrowed JSON text value.
    value: &'value T,
    /// Policy used to redact parsed JSON.
    policy: &'policy crate::RedactionPolicy,
}

#[cfg(feature = "json")]
impl<'value, 'policy, T: ?Sized> RedactedJsonSerializeRef<'value, 'policy, T> {
    /// Creates a policy-carrying borrowed JSON adapter.
    #[must_use]
    pub fn new(value: &'value T, policy: &'policy crate::RedactionPolicy) -> Self {
        Self { value, policy }
    }
}

#[cfg(feature = "json")]
impl<T: ?Sized + RedactJsonSerialize> serde::Serialize for RedactedJsonSerializeRef<'_, '_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.value.serialize_redacted_json(serializer, self.policy)
    }
}

/// Parses and redacts one JSON text value for Serde publication.
#[cfg(feature = "json")]
fn serialize_json_text<S>(serializer: S, text: &str, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let masked = || policy.masking().mask_opaque(crate::Sensitivity::Secret);
    if !admit_input(text.len()) {
        let replacement = masked();
        return serializer.serialize_str(replacement.as_ref());
    }
    if policy.is_disabled() {
        return serializer.serialize_str(text);
    }
    if text.len() > policy.limits().max_input_bytes() {
        let replacement = masked();
        return serializer.serialize_str(replacement.as_ref());
    }
    if !crate::formats::json::is_valid_json_text(text) {
        let replacement = masked();
        return serializer.serialize_str(replacement.as_ref());
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        let replacement = masked();
        return serializer.serialize_str(replacement.as_ref());
    };
    if !admit_structured_json_value(&value) {
        let replacement = masked();
        return serializer.serialize_str(replacement.as_ref());
    }
    let output = crate::formats::json::redact_json_value_with_limit(policy, &value, usize::MAX);
    serializer.serialize_str(output.text())
}

/// Admits every node and item in a parsed JSON value.
#[cfg(feature = "json")]
fn admit_structured_json_value(value: &serde_json::Value) -> bool {
    if !admit_node() {
        return false;
    }
    let admitted = match value {
        serde_json::Value::Array(values) => values
            .iter()
            .all(|value| admit_collection_items(1) && admit_structured_json_value(value)),
        serde_json::Value::Object(entries) => entries
            .values()
            .all(|value| admit_collection_items(1) && admit_structured_json_value(value)),
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => true,
    };
    leave_node();
    admitted
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for String {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_json_text(serializer, self.as_str(), policy)
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for str {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_json_text(serializer, self, policy)
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for &str {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_json_text(serializer, self, policy)
    }
}

#[cfg(feature = "json")]
impl<'a> RedactJsonSerialize for Cow<'a, str> {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_json_text(serializer, self.as_ref(), policy)
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for Option<String> {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Some(value) => serialize_json_text(serializer, value, policy),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(feature = "json")]
impl RedactJsonSerialize for Option<&str> {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Some(value) => serialize_json_text(serializer, value, policy),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(feature = "json")]
impl<'a> RedactJsonSerialize for Option<Cow<'a, str>> {
    fn serialize_redacted_json<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Some(value) => serialize_json_text(serializer, value, policy),
            None => serializer.serialize_none(),
        }
    }
}

macro_rules! tuple_redact_serialize {
    ($count:expr; $($name:ident => $index:tt),+) => {
        impl<$($name: RedactSerialize),+> RedactSerialize for ($($name,)+) {
            fn serialize_redacted<S>(&self, serializer: S, policy: &crate::RedactionPolicy) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if !admit_collection_items($count) {
                    return serializer.serialize_str(
                        policy
                            .masking()
                            .mask_opaque(crate::Sensitivity::Secret)
                            .as_ref(),
                    );
                }
                let mut tuple = serializer.serialize_tuple($count)?;
                $(tuple.serialize_element(&RedactedSerializeRef::new(&self.$index, policy))?;)+
                tuple.end()
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

#[cfg(all(test, feature = "serde"))]
mod tests {
    use bigdecimal::BigDecimal;

    use super::RedactSerializeScope;
    use super::RedactedLevelSerializeRef;
    use crate::RedactionPolicy;
    use crate::Sensitivity;

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
