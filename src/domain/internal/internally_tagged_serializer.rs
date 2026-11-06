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
/// # Errors
///
/// Returns the underlying serializer's error when the value cannot be
/// represented as a map or when the serializer rejects an emitted entry.
///
/// # Type Parameters
///
/// - `S`: Destination serializer.
/// - `T`: Possibly unsized serializable payload.
///
/// # Parameters
///
/// - `serializer`: Destination receiving the map with its injected tag.
/// - `enum_name`: Source enum name used in shape errors.
/// - `variant_name`: Source variant name used in shape errors.
/// - `tag`: Injected static map key.
/// - `tag_value`: Variant label charged as scalar payload.
/// - `value`: Map-like source payload.
///
/// # Returns
///
/// The downstream result after the admitted representation is serialized.
#[doc(hidden)]
#[inline(always)]
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
///
/// # Type Parameters
///
/// - `S`: Downstream serializer used to construct the tagged map.
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

macro_rules! reject_scalar_methods {
    ($($method:ident : $value:ty),* $(,)?) => {
        $(
            /// Rejects a non-map payload without invoking its value serializer.
            ///
            /// # Errors
            ///
            /// Always returns an error because the payload is not a map or struct.
            ///
            /// # Parameters
            ///
            /// - `_value`: Source event value. Ignored because this shape is rejected.
            ///
            /// # Returns
            ///
            /// No success value; this unsupported shape is always rejected.
            #[inline(always)]
            fn $method(self, _value: $value) -> Result<Self::Ok, Self::Error> {
                self.unsupported()
            }
        )*
    };
}

impl<S: Serializer> Serializer for InternallyTaggedSerializer<S> {
    /// Underlying serializer success value.
    type Ok = S::Ok;
    /// Underlying serializer error including shape rejection.
    type Error = S::Error;
    /// Rejects sequence payloads because only maps and structs are supported.
    type SerializeSeq = Impossible<S::Ok, S::Error>;
    /// Rejects tuple payloads because only maps and structs are supported.
    type SerializeTuple = Impossible<S::Ok, S::Error>;
    /// Rejects tuple-struct payloads because only maps and structs are
    /// supported.
    type SerializeTupleStruct = Impossible<S::Ok, S::Error>;
    /// Rejects tuple-variant payloads because only maps and structs are
    /// supported.
    type SerializeTupleVariant = Impossible<S::Ok, S::Error>;
    /// Map adapter that emits the injected tag and forwards map entries.
    type SerializeMap = InternallyTaggedMap<S::SerializeMap>;
    /// Map adapter that emits the injected tag and forwards struct fields.
    type SerializeStruct = InternallyTaggedMap<S::SerializeMap>;
    /// Rejects struct-variant payloads because only maps and structs are
    /// supported.
    type SerializeStructVariant = Impossible<S::Ok, S::Error>;

    /// Preserves the destination serializer's human-readable representation.
    ///
    /// # Returns
    ///
    /// `true` when the destination requests human-readable data; `false` when
    /// it requests a compact representation.
    #[inline(always)]
    fn is_human_readable(&self) -> bool {
        self.serializer.is_human_readable()
    }

    /// Admits and injects the tag before returning a map adapter.
    ///
    /// # Errors
    ///
    /// Propagates tag admission or downstream map serialization errors.
    ///
    /// # Parameters
    ///
    /// - `length`: Some declared entries before the injected tag, or None for
    ///   an unknown length.
    ///
    /// # Returns
    ///
    /// The admitted compound adapter used to serialize its children.
    fn serialize_map(self, length: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        admit_serialize_items::<S::Error>(1)?;
        let mut map = self
            .serializer
            .serialize_map(length.map(|length| length.saturating_add(1)))?;
        map.serialize_entry(self.tag, &BudgetSerialize::new(self.tag_value))?;
        Ok(InternallyTaggedMap { map })
    }

    /// Forwards the struct as a map with one additional tag entry.
    ///
    /// # Errors
    ///
    /// Propagates tag admission or downstream map serialization errors.
    ///
    /// # Parameters
    ///
    /// - `_name`: Static source type name. Not needed when forwarding the
    ///   struct as a map.
    /// - `length`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// The admitted compound adapter used to serialize its children.
    #[inline(always)]
    fn serialize_struct(self, _name: &'static str, length: usize) -> Result<Self::SerializeStruct, Self::Error> {
        self.serialize_map(Some(length))
    }

    reject_scalar_methods! {
        serialize_bool: bool,
        serialize_i8: i8, serialize_i16: i16, serialize_i32: i32,
        serialize_i64: i64, serialize_i128: i128,
        serialize_u8: u8, serialize_u16: u16, serialize_u32: u32,
        serialize_u64: u64, serialize_u128: u128,
        serialize_f32: f32, serialize_f64: f64,
        serialize_char: char, serialize_str: &str, serialize_bytes: &[u8],
    }
    /// Rejects an option payload without invoking a value serializer.
    ///
    /// # Errors
    ///
    /// Always returns an error because the payload is not a map or struct.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline(always)]
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    /// Rejects an option payload with a value without invoking its serializer.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized serializable payload type, whose serializer is
    ///   not invoked because option payloads are rejected.
    ///
    /// # Errors
    ///
    /// Always returns an error because the payload is not a map or struct.
    ///
    /// # Parameters
    ///
    /// - `_value`: Source event value. Ignored because this shape is rejected.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline(always)]
    fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    /// Serializes a unit payload as a tag-only map.
    ///
    /// # Errors
    ///
    /// Returns a destination error if tag admission or map serialization fails.
    ///
    /// # Returns
    ///
    /// The destination serializer's successful map result.
    #[inline(always)]
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.serialize_map(Some(0))?.end()
    }
    /// Serializes a unit struct using the accepted unit representation.
    ///
    /// # Errors
    ///
    /// Returns a destination error if tag admission or map serialization fails.
    ///
    /// # Parameters
    ///
    /// - `_name`: Static source type name, unused by the map representation.
    ///
    /// # Returns
    ///
    /// The destination serializer's successful map result.
    #[inline(always)]
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.serialize_unit()
    }
    /// Rejects a unit enum variant payload, which is not a map or struct.
    ///
    /// # Errors
    ///
    /// Always returns an error because the payload is not a map or struct.
    ///
    /// # Parameters
    ///
    /// - `_name`: Static enum type name. Ignored because this shape is
    ///   rejected.
    /// - `_variant_index`: Source variant index. Ignored because this shape is
    ///   rejected.
    /// - `_variant`: Static variant label. Ignored because this shape is
    ///   rejected.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline(always)]
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    /// Forwards a newtype wrapper to this adapter.
    ///
    /// # Errors
    ///
    /// Returns the destination result for wrapped maps or structs. Other
    /// underlying shapes produce the adapter's unsupported-shape error.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized serializable source type.
    ///
    /// # Parameters
    ///
    /// - `_name`: Static wrapper name, which does not alter the payload event.
    /// - `value`: Wrapped source value serialized through this adapter.
    ///
    /// # Returns
    ///
    /// The destination serializer's result for the wrapped payload.
    #[inline(always)]
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }
    /// Rejects a non-map payload without invoking its value serializer.
    ///
    /// # Errors
    ///
    /// Always returns an error because the payload is not a map or struct.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized serializable source type.
    ///
    /// # Parameters
    ///
    /// - `_name`: Static source type name. Ignored because this shape is
    ///   rejected.
    /// - `_variant_index`: Source variant index. Ignored because this shape is
    ///   rejected.
    /// - `_variant`: Static variant label. Ignored because this shape is
    ///   rejected.
    /// - `_value`: Source event value. Ignored because this shape is rejected.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline(always)]
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.unsupported()
    }
    /// Rejects a non-map payload without invoking its value serializer.
    ///
    /// # Errors
    ///
    /// Always returns an error because the payload is not a map or struct.
    ///
    /// # Parameters
    ///
    /// - `_length`: Declared collection length. Ignored because this shape is
    ///   rejected.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline(always)]
    fn serialize_seq(self, _length: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.unsupported()
    }
    /// Rejects a non-map payload without invoking its value serializer.
    ///
    /// # Errors
    ///
    /// Always returns an error because the payload is not a map or struct.
    ///
    /// # Parameters
    ///
    /// - `_length`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline(always)]
    fn serialize_tuple(self, _length: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.unsupported()
    }
    /// Rejects a non-map payload without invoking its value serializer.
    ///
    /// # Errors
    ///
    /// Always returns an error because the payload is not a map or struct.
    ///
    /// # Parameters
    ///
    /// - `_name`: Static source type name. Ignored because this shape is
    ///   rejected.
    /// - `_length`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline(always)]
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.unsupported()
    }
    /// Rejects a non-map payload without invoking its value serializer.
    ///
    /// # Errors
    ///
    /// Always returns an error because the payload is not a map or struct.
    ///
    /// # Parameters
    ///
    /// - `_name`: Static source type name. Ignored because this shape is
    ///   rejected.
    /// - `_variant_index`: Source variant index. Ignored because this shape is
    ///   rejected.
    /// - `_variant`: Static variant label. Ignored because this shape is
    ///   rejected.
    /// - `_length`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline(always)]
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.unsupported()
    }
    /// Rejects a non-map payload without invoking its value serializer.
    ///
    /// # Errors
    ///
    /// Always returns an error because the payload is not a map or struct.
    ///
    /// # Parameters
    ///
    /// - `_name`: Static source type name. Ignored because this shape is
    ///   rejected.
    /// - `_variant_index`: Source variant index. Ignored because this shape is
    ///   rejected.
    /// - `_variant`: Static variant label. Ignored because this shape is
    ///   rejected.
    /// - `_length`: Declared number of collection entries.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline(always)]
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
    ///
    /// # Errors
    ///
    /// Always returns a serializer error naming the enum and variant.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Nominal success type; this helper never returns success.
    ///
    /// # Returns
    ///
    /// No success value; this unsupported shape is always rejected.
    #[inline]
    fn unsupported<T>(self) -> Result<T, S::Error> {
        Err(SerdeError::custom(format_args!(
            "cannot serialize internally tagged {} variant {} newtype from a non-map value",
            self.enum_name, self.variant_name,
        )))
    }
}
