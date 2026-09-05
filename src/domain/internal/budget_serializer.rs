// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Single-pass admission of ordinary Serde events.

use serde::Serialize;
use serde::Serializer;
use serde::ser::Error as SerdeError;

use super::bounded_display_writer::BoundedDisplayWriter;
use super::budget_compound::BudgetCompound;
use super::budget_serialize::BudgetSerialize;
use super::redact_serialize_scope::admit_collection_items;
use super::redact_serialize_scope::admit_input;
use super::redact_serialize_scope::admit_output;
use super::redact_serialize_scope::remaining_input_bytes;
use super::redact_serialize_scope::remaining_output_bytes;

/// Streams Serde events through the active shared resource budget.
pub(super) struct BudgetSerializer<S> {
    pub(super) inner: S,
}

/// Charges one scalar's logical bytes before forwarding it.
/// Returns a serializer error for either source or payload exhaustion.
fn scalar<E: SerdeError>(bytes: usize) -> Result<(), E> {
    if !admit_input(bytes) {
        return Err(E::custom("redaction input budget exceeded"));
    }
    if !admit_output(bytes) {
        return Err(E::custom("redaction scalar output budget exceeded"));
    }
    Ok(())
}

/// Charges collection entries before invoking any child serializer.
pub(super) fn items<E: SerdeError>(count: usize) -> Result<(), E> {
    if admit_collection_items(count) {
        Ok(())
    } else {
        Err(E::custom("redaction collection budget exceeded"))
    }
}

impl<S: Serializer> Serializer for BudgetSerializer<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = BudgetCompound<S::SerializeSeq>;
    type SerializeTuple = BudgetCompound<S::SerializeTuple>;
    type SerializeTupleStruct = BudgetCompound<S::SerializeTupleStruct>;
    type SerializeTupleVariant = BudgetCompound<S::SerializeTupleVariant>;
    type SerializeMap = BudgetCompound<S::SerializeMap>;
    type SerializeStruct = BudgetCompound<S::SerializeStruct>;
    type SerializeStructVariant = BudgetCompound<S::SerializeStructVariant>;
    fn serialize_bool(self, value: bool) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_bool(value)
    }
    fn serialize_i8(self, value: i8) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i8(value)
    }
    fn serialize_i16(self, value: i16) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i16(value)
    }
    fn serialize_i32(self, value: i32) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i32(value)
    }
    fn serialize_i64(self, value: i64) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i64(value)
    }
    fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_i128(value)
    }
    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u8(value)
    }
    fn serialize_u16(self, value: u16) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u16(value)
    }
    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u32(value)
    }
    fn serialize_u64(self, value: u64) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u64(value)
    }
    fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_u128(value)
    }
    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_f32(value)
    }
    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.to_string().len())?;
        self.inner.serialize_f64(value)
    }
    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.len_utf8())?;
        self.inner.serialize_char(value)
    }
    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.len())?;
        self.inner.serialize_str(value)
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(value.len())?;
        self.inner.serialize_bytes(value)
    }
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(0)?;
        self.inner.serialize_none()
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(0)?;
        self.inner.serialize_unit()
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_some(&BudgetSerialize::new(value))
    }
    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_unit_struct(name)
    }
    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        scalar::<S::Error>(variant.len())?;
        self.inner.serialize_unit_variant(name, index, variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_newtype_struct(name, &BudgetSerialize::new(value))
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.inner
            .serialize_newtype_variant(name, index, variant, &BudgetSerialize::new(value))
    }
    fn collect_str<T: ?Sized + std::fmt::Display>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        let mut writer = BoundedDisplayWriter::new(remaining_input_bytes().min(remaining_output_bytes()));
        std::fmt::write(&mut writer, format_args!("{value}"))
            .map_err(|_| SerdeError::custom("redaction input budget exceeded"))?;
        self.serialize_str(&writer.finish())
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        if let Some(count) = len {
            items::<S::Error>(count)?;
        }
        Ok(BudgetCompound {
            inner: self.inner.serialize_seq(len)?,
            remaining: len.unwrap_or(0),
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_tuple(len)?,
            remaining: len,
        })
    }
    fn serialize_tuple_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeTupleStruct, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_tuple_struct(name, len)?,
            remaining: len,
        })
    }
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_tuple_variant(name, index, variant, len)?,
            remaining: len,
        })
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        if let Some(count) = len {
            items::<S::Error>(count)?;
        }
        Ok(BudgetCompound {
            inner: self.inner.serialize_map(len)?,
            remaining: len.unwrap_or(0),
        })
    }
    fn serialize_struct(self, name: &'static str, len: usize) -> Result<Self::SerializeStruct, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_struct(name, len)?,
            remaining: len,
        })
    }
    fn serialize_struct_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        items::<S::Error>(len)?;
        Ok(BudgetCompound {
            inner: self.inner.serialize_struct_variant(name, index, variant, len)?,
            remaining: len,
        })
    }
}
