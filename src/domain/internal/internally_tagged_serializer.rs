// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serializer adapter for redacted internally tagged newtype variants.

use serde::{
    Serialize, Serializer,
    ser::{Impossible, SerializeMap, SerializeStruct},
};

/// Serializer that inserts an enum tag before map-like newtype content.
///
/// # Type Parameters
///
/// * `S` - Underlying Serde serializer receiving the tagged representation.
struct InternallyTaggedSerializer<S> {
    /// Underlying serializer receiving the merged representation.
    serializer: S,
    /// Owning enum name used in errors.
    type_name: &'static str,
    /// Rust variant name used in errors.
    variant_identifier: &'static str,
    /// Serialized tag field name.
    tag: &'static str,
    /// Serialized variant name stored in the tag.
    variant_name: &'static str,
}

impl<S> InternallyTaggedSerializer<S>
where
    S: Serializer,
{
    /// Creates an unsupported-content serializer error.
    ///
    /// # Parameters
    ///
    /// * `kind` - Human-readable content kind rejected by internal tagging.
    ///
    /// # Returns
    ///
    /// The underlying serializer's custom error type.
    ///
    /// # Errors
    ///
    /// Always constructs an error because `kind` cannot carry an internal tag.
    fn unsupported(self, kind: &str) -> S::Error {
        <S::Error as serde::ser::Error>::custom(format_args!(
            "cannot serialize internally tagged redacted newtype variant {}::{} containing {kind}",
            self.type_name, self.variant_identifier,
        ))
    }
}

impl<S> Serializer for InternallyTaggedSerializer<S>
where
    S: Serializer,
{
    type Error = S::Error;
    type Ok = S::Ok;
    type SerializeMap = S::SerializeMap;
    type SerializeSeq = Impossible<S::Ok, S::Error>;
    type SerializeStruct = S::SerializeStruct;
    type SerializeStructVariant = Impossible<S::Ok, S::Error>;
    type SerializeTuple = Impossible<S::Ok, S::Error>;
    type SerializeTupleStruct = Impossible<S::Ok, S::Error>;
    type SerializeTupleVariant = Impossible<S::Ok, S::Error>;

    /// Rejects boolean content because it cannot carry an inserted tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Boolean value rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_bool(self, _value: bool) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("a boolean"))
    }

    /// Rejects signed integer content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Signed integer rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_i8(self, _value: i8) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("an integer"))
    }

    /// Rejects signed integer content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Signed integer rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_i16(self, _value: i16) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("an integer"))
    }

    /// Rejects signed integer content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Signed integer rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_i32(self, _value: i32) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("an integer"))
    }

    /// Rejects signed integer content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Signed integer rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_i64(self, _value: i64) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("an integer"))
    }

    /// Rejects unsigned integer content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Unsigned integer rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_u8(self, _value: u8) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("an integer"))
    }

    /// Rejects unsigned integer content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Unsigned integer rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_u16(self, _value: u16) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("an integer"))
    }

    /// Rejects unsigned integer content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Unsigned integer rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_u32(self, _value: u32) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("an integer"))
    }

    /// Rejects unsigned integer content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Unsigned integer rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_u64(self, _value: u64) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("an integer"))
    }

    /// Rejects floating-point content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Floating-point value rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_f32(self, _value: f32) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("a float"))
    }

    /// Rejects floating-point content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Floating-point value rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_f64(self, _value: f64) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("a float"))
    }

    /// Rejects character content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Character rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_char(self, _value: char) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("a character"))
    }

    /// Rejects string content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - String slice rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_str(self, _value: &str) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("a string"))
    }

    /// Rejects byte-array content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_value` - Byte slice rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_bytes(self, _value: &[u8]) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("a byte array"))
    }

    /// Rejects absent optional content because it cannot carry a tag field.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Err(self.unsupported("an optional"))
    }

    /// Rejects present optional content because it cannot carry a tag field.
    ///
    /// # Type Parameters
    ///
    /// * `T` - Serializable optional content rejected by this adapter.
    ///
    /// # Parameters
    ///
    /// * `_value` - Present optional content rejected by this adapter.
    ///
    /// # Returns
    ///
    /// No successful value; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_some<T>(self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        Err(self.unsupported("an optional"))
    }

    /// Serializes unit content as a map containing only the inserted tag.
    ///
    /// # Returns
    ///
    /// The underlying serializer's completed map output.
    ///
    /// # Errors
    ///
    /// Returns an underlying serializer error when the map, tag entry, or map
    /// completion cannot be serialized.
    #[inline]
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        let mut map = self.serializer.serialize_map(Some(1))?;
        map.serialize_entry(self.tag, self.variant_name)?;
        map.end()
    }

    /// Serializes unit-struct content as a map containing only the tag.
    ///
    /// # Parameters
    ///
    /// * `_name` - Unit-struct name, unused by the internal-tag representation.
    ///
    /// # Returns
    ///
    /// The underlying serializer's completed map output.
    ///
    /// # Errors
    ///
    /// Returns an underlying serializer error when the tag-only map cannot be
    /// serialized.
    #[inline]
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.serialize_unit()
    }

    /// Serializes a nested unit variant beside the inserted outer tag.
    ///
    /// # Parameters
    ///
    /// * `_name` - Owning enum name, unused by this representation.
    /// * `_index` - Variant index, unused by this representation.
    /// * `inner_variant` - Nested variant name written beside the outer tag.
    ///
    /// # Returns
    ///
    /// The underlying serializer's completed map output.
    ///
    /// # Errors
    ///
    /// Returns an underlying serializer error when the map or either entry
    /// cannot be serialized.
    #[inline]
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        inner_variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        let mut map = self.serializer.serialize_map(Some(2))?;
        map.serialize_entry(self.tag, self.variant_name)?;
        map.serialize_entry(inner_variant, &())?;
        map.end()
    }

    /// Transparently unwraps a newtype struct before inserting the tag.
    ///
    /// # Type Parameters
    ///
    /// * `T` - Serializable newtype value.
    ///
    /// # Parameters
    ///
    /// * `_name` - Newtype-struct name, unused by this representation.
    /// * `value` - Wrapped value serialized through this adapter.
    ///
    /// # Returns
    ///
    /// The underlying serializer's output for `value`.
    ///
    /// # Errors
    ///
    /// Returns the error produced while serializing `value`.
    #[inline]
    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        value.serialize(self)
    }

    /// Serializes a nested newtype variant beside the inserted outer tag.
    ///
    /// # Type Parameters
    ///
    /// * `T` - Serializable nested newtype value.
    ///
    /// # Parameters
    ///
    /// * `_name` - Owning enum name, unused by this representation.
    /// * `_index` - Variant index, unused by this representation.
    /// * `inner_variant` - Nested variant name written beside the outer tag.
    /// * `value` - Nested variant value.
    ///
    /// # Returns
    ///
    /// The underlying serializer's completed map output.
    ///
    /// # Errors
    ///
    /// Returns an underlying serializer error when the map, either entry, or
    /// nested value cannot be serialized.
    #[inline]
    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _index: u32,
        inner_variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize + ?Sized,
    {
        let mut map = self.serializer.serialize_map(Some(2))?;
        map.serialize_entry(self.tag, self.variant_name)?;
        map.serialize_entry(inner_variant, value)?;
        map.end()
    }

    /// Rejects sequence content because it cannot carry a named tag field.
    ///
    /// # Parameters
    ///
    /// * `_length` - Optional sequence length, unused because sequences are
    ///   rejected.
    ///
    /// # Returns
    ///
    /// No sequence state; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_seq(self, _length: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Err(self.unsupported("a sequence"))
    }

    /// Rejects tuple content because it cannot carry a named tag field.
    ///
    /// # Parameters
    ///
    /// * `_length` - Tuple length, unused because tuples are rejected.
    ///
    /// # Returns
    ///
    /// No tuple state; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_tuple(self, _length: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(self.unsupported("a tuple"))
    }

    /// Rejects tuple-struct content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_name` - Tuple-struct name, unused because tuple structs are
    ///   rejected.
    /// * `_length` - Tuple-struct length, unused because tuple structs are
    ///   rejected.
    ///
    /// # Returns
    ///
    /// No tuple-struct state; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(self.unsupported("a tuple struct"))
    }

    /// Rejects tuple-variant content because it cannot carry a tag field.
    ///
    /// # Parameters
    ///
    /// * `_name` - Owning enum name, unused because tuple variants are
    ///   rejected.
    /// * `_index` - Variant index, unused because tuple variants are rejected.
    /// * `_variant` - Variant name, unused because tuple variants are rejected.
    /// * `_length` - Variant length, unused because tuple variants are
    ///   rejected.
    ///
    /// # Returns
    ///
    /// No tuple-variant state; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(self.unsupported("a tuple variant"))
    }

    /// Starts map content after serializing the inserted tag entry.
    ///
    /// # Parameters
    ///
    /// * `length` - Optional number of original map entries before inserting
    ///   the tag.
    ///
    /// # Returns
    ///
    /// Map state with the internal tag entry already serialized.
    ///
    /// # Errors
    ///
    /// Returns an underlying serializer error when the map or tag entry cannot
    /// be serialized.
    #[inline]
    fn serialize_map(self, length: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        let mut map = self
            .serializer
            .serialize_map(length.map(|value| value + 1))?;
        map.serialize_entry(self.tag, self.variant_name)?;
        Ok(map)
    }

    /// Starts struct content after serializing the inserted tag field.
    ///
    /// # Parameters
    ///
    /// * `name` - Struct name forwarded to the underlying serializer.
    /// * `length` - Number of original fields before inserting the tag.
    ///
    /// # Returns
    ///
    /// Struct state with the internal tag field already serialized.
    ///
    /// # Errors
    ///
    /// Returns an underlying serializer error when the struct or tag field
    /// cannot be serialized.
    #[inline]
    fn serialize_struct(
        self,
        name: &'static str,
        length: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        let mut state = self.serializer.serialize_struct(name, length + 1)?;
        state.serialize_field(self.tag, self.variant_name)?;
        Ok(state)
    }

    /// Rejects struct-variant content because it introduces nested tagging.
    ///
    /// # Parameters
    ///
    /// * `_name` - Owning enum name, unused because struct variants are
    ///   rejected.
    /// * `_index` - Variant index, unused because struct variants are rejected.
    /// * `_variant` - Variant name, unused because struct variants are
    ///   rejected.
    /// * `_length` - Variant length, unused because struct variants are
    ///   rejected.
    ///
    /// # Returns
    ///
    /// No struct-variant state; this method always returns an error.
    ///
    /// # Errors
    ///
    /// Always returns a custom unsupported-content serializer error.
    #[inline]
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _length: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(self.unsupported("a struct variant"))
    }
}

/// Serializes map-like newtype content with an inserted internal enum tag.
///
/// # Type Parameters
///
/// * `S` - Destination serializer type.
/// * `T` - Serializable newtype-content type.
///
/// # Parameters
///
/// * `serializer` - Destination serializer.
/// * `type_name` - Owning enum name used in diagnostics.
/// * `variant_identifier` - Rust variant name used in diagnostics.
/// * `tag` - Serialized tag field name.
/// * `variant_name` - Serialized variant name stored in the tag.
/// * `value` - Redacted newtype content.
///
/// # Returns
///
/// The destination serializer's successful output.
///
/// # Errors
///
/// Returns the serializer error unchanged, or a custom error when `value`
/// serializes as a primitive, optional, or sequence that cannot carry a tag.
pub fn serialize_internally_tagged<S, T>(
    serializer: S,
    type_name: &'static str,
    variant_identifier: &'static str,
    tag: &'static str,
    variant_name: &'static str,
    value: &T,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize + ?Sized,
{
    value.serialize(InternallyTaggedSerializer {
        serializer,
        type_name,
        variant_identifier,
        tag,
        variant_name,
    })
}
