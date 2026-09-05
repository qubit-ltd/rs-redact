// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serializer that injects an internal enum tag into map-like payloads.

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as SerdeError;
use serde::ser::Impossible;
use serde::ser::SerializeMap;

use super::budget_serialize::BudgetSerialize;
use super::internally_tagged_map::InternallyTaggedMap;
use super::serde_admission::admit_serialize_items;

/// Serializes a map-like value with one internally tagged enum field.
///
/// Requires an active [`super::RedactSerializeScope`], normally installed by
/// the generated caller, so the injected tag shares the caller's budget.
///
/// Returns the underlying serializer's error when the value cannot be
/// represented as a map or when the serializer rejects an emitted entry.
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
    S: Serializer,
    T: Serialize + ?Sized,
{
    value.serialize(InternallyTaggedSerializer {
        serializer,
        enum_name,
        variant_name,
        tag,
        tag_value,
    })
}

/// Adapts a serializer so only map-like values can receive an internal tag.
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

impl<S: Serializer> Serializer for InternallyTaggedSerializer<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = Impossible<S::Ok, S::Error>;
    type SerializeTuple = Impossible<S::Ok, S::Error>;
    type SerializeTupleStruct = Impossible<S::Ok, S::Error>;
    type SerializeTupleVariant = Impossible<S::Ok, S::Error>;
    type SerializeMap = InternallyTaggedMap<S::SerializeMap>;
    type SerializeStruct = InternallyTaggedMap<S::SerializeMap>;
    type SerializeStructVariant = Impossible<S::Ok, S::Error>;

    fn serialize_map(self, length: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        admit_serialize_items::<S::Error>(1)?;
        let mut map = self
            .serializer
            .serialize_map(length.map(|length| length.saturating_add(1)))?;
        map.serialize_entry(self.tag, &BudgetSerialize::new(self.tag_value))?;
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
    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Self::Ok, Self::Error> {
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
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
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

impl<S: Serializer> InternallyTaggedSerializer<S> {
    /// Reports that internally tagged newtypes require a map-like payload.
    fn unsupported<T>(self) -> Result<T, S::Error> {
        Err(SerdeError::custom(format_args!(
            "cannot serialize internally tagged {} variant {} newtype from a non-map value",
            self.enum_name, self.variant_name,
        )))
    }
}
